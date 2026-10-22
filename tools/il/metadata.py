"""A dependency-free ECMA-335 metadata and IL reader.

The whole investigation rests on reading `ColokTool.exe`'s managed metadata:
type/method/field tables, signatures, string literals, `FieldRVA` initialised
arrays, `ImplMap` P/Invoke targets, and method bodies.  Every claim in
`docs/` that cites an IL offset comes from this module, so it lives in the
repo rather than in scratch space.

Scope: enough of ECMA-335 II.22 (tables), II.23.2 (signatures) and
III (instruction set) to disassemble a .NET Framework 4.x IL-only assembly.
Not a general-purpose library; no support for mixed-mode images, ENC,
pointer tables (`FieldPtr`/`MethodPtr`/`ParamPtr`), or 64-bit metadata
streams beyond what the format requires.
"""

import struct

# --------------------------------------------------------------------------
# table ids (ECMA-335 II.22)
# --------------------------------------------------------------------------
(T_MODULE, T_TYPEREF, T_TYPEDEF, T_FIELDPTR, T_FIELD, T_METHODPTR,
 T_METHODDEF, T_PARAMPTR, T_PARAM, T_INTERFACEIMPL, T_MEMBERREF, T_CONSTANT,
 T_CUSTOMATTRIBUTE, T_FIELDMARSHAL, T_DECLSECURITY, T_CLASSLAYOUT,
 T_FIELDLAYOUT, T_STANDALONESIG, T_EVENTMAP, T_EVENTPTR, T_EVENT,
 T_PROPERTYMAP, T_PROPERTYPTR, T_PROPERTY, T_METHODSEMANTICS, T_METHODIMPL,
 T_MODULEREF, T_TYPESPEC, T_IMPLMAP, T_FIELDRVA, T_ENCLOG, T_ENCMAP,
 T_ASSEMBLY, T_ASSEMBLYPROCESSOR, T_ASSEMBLYOS, T_ASSEMBLYREF,
 T_ASSEMBLYREFPROCESSOR, T_ASSEMBLYREFOS, T_FILE, T_EXPORTEDTYPE,
 T_MANIFESTRESOURCE, T_NESTEDCLASS, T_GENERICPARAM, T_METHODSPEC,
 T_GENERICPARAMCONSTRAINT) = range(45)

TABLE_NAMES = [
    'Module', 'TypeRef', 'TypeDef', 'FieldPtr', 'Field', 'MethodPtr',
    'MethodDef', 'ParamPtr', 'Param', 'InterfaceImpl', 'MemberRef',
    'Constant', 'CustomAttribute', 'FieldMarshal', 'DeclSecurity',
    'ClassLayout', 'FieldLayout', 'StandAloneSig', 'EventMap', 'EventPtr',
    'Event', 'PropertyMap', 'PropertyPtr', 'Property', 'MethodSemantics',
    'MethodImpl', 'ModuleRef', 'TypeSpec', 'ImplMap', 'FieldRVA', 'ENCLog',
    'ENCMap', 'Assembly', 'AssemblyProcessor', 'AssemblyOS', 'AssemblyRef',
    'AssemblyRefProcessor', 'AssemblyRefOS', 'File', 'ExportedType',
    'ManifestResource', 'NestedClass', 'GenericParam', 'MethodSpec',
    'GenericParamConstraint',
]

# --------------------------------------------------------------------------
# coded index definitions (ECMA-335 II.24.2.6)
# --------------------------------------------------------------------------
# The tag width is fixed by the spec and is *not* always ceil(log2(tables)).
CODED_BITS = {
    'TypeDefOrRef': 2, 'HasConstant': 2, 'HasCustomAttribute': 5,
    'HasFieldMarshal': 1, 'HasDeclSecurity': 2, 'MemberRefParent': 3,
    'HasSemantics': 1, 'MethodDefOrRef': 1, 'MemberForwarded': 1,
    'Implementation': 2, 'CustomAttributeType': 3, 'ResolutionScope': 2,
    'TypeOrMethodDef': 1,
}

CODED = {
    'TypeDefOrRef': [(T_TYPEDEF, 2), (T_TYPEREF, 2), (T_TYPESPEC, 2)],
    'HasConstant': [(T_FIELD, 2), (T_PARAM, 2), (T_PROPERTY, 2)],
    'HasCustomAttribute': [
        (T_METHODDEF, 5), (T_FIELD, 5), (T_TYPEREF, 5), (T_TYPEDEF, 5),
        (T_PARAM, 5), (T_INTERFACEIMPL, 5), (T_MEMBERREF, 5), (T_MODULE, 5),
        (T_DECLSECURITY, 5), (T_PROPERTY, 5), (T_EVENT, 5),
        (T_STANDALONESIG, 5), (T_MODULEREF, 5), (T_TYPESPEC, 5),
        (T_ASSEMBLY, 5), (T_ASSEMBLYREF, 5), (T_FILE, 5), (T_EXPORTEDTYPE, 5),
        (T_MANIFESTRESOURCE, 5), (T_GENERICPARAM, 5),
        (T_GENERICPARAMCONSTRAINT, 5), (T_METHODSPEC, 5)],
    'HasFieldMarshal': [(T_FIELD, 1), (T_PARAM, 1)],
    'HasDeclSecurity': [(T_TYPEDEF, 2), (T_METHODDEF, 2), (T_ASSEMBLY, 2)],
    'MemberRefParent': [(T_TYPEDEF, 3), (T_TYPEREF, 3), (T_MODULEREF, 3),
                        (T_METHODDEF, 3), (T_TYPESPEC, 3)],
    'HasSemantics': [(T_EVENT, 1), (T_PROPERTY, 1)],
    'MethodDefOrRef': [(T_METHODDEF, 1), (T_MEMBERREF, 1)],
    'MemberForwarded': [(T_FIELD, 1), (T_METHODDEF, 1)],
    'Implementation': [(T_FILE, 2), (T_ASSEMBLYREF, 2), (T_EXPORTEDTYPE, 2)],
    # tags 0 and 1 are unused
    'CustomAttributeType': [(None, 3), (None, 3), (T_METHODDEF, 3),
                            (T_MEMBERREF, 3)],
    'ResolutionScope': [(T_MODULE, 2), (T_MODULEREF, 2), (T_ASSEMBLYREF, 2),
                        (T_TYPEREF, 2)],
    'TypeOrMethodDef': [(T_TYPEDEF, 1), (T_METHODDEF, 1)],
}

# --------------------------------------------------------------------------
# table schemas: (column name, kind)
#   kinds: 'u8' 'u16' 'u32' 'str' 'guid' 'blob'
#          ('table', id)  -> simple index into that table
#          '<CodedName>'  -> coded index
# --------------------------------------------------------------------------
SCHEMA = {
    T_MODULE: [('Generation', 'u16'), ('Name', 'str'), ('Mvid', 'guid'),
               ('EncId', 'guid'), ('EncBaseId', 'guid')],
    T_TYPEREF: [('ResolutionScope', 'ResolutionScope'), ('Name', 'str'),
                ('Namespace', 'str')],
    T_TYPEDEF: [('Flags', 'u32'), ('Name', 'str'), ('Namespace', 'str'),
                ('Extends', 'TypeDefOrRef'), ('FieldList', ('table', T_FIELD)),
                ('MethodList', ('table', T_METHODDEF))],
    T_FIELD: [('Flags', 'u16'), ('Name', 'str'), ('Signature', 'blob')],
    T_METHODDEF: [('RVA', 'u32'), ('ImplFlags', 'u16'), ('Flags', 'u16'),
                  ('Name', 'str'), ('Signature', 'blob'),
                  ('ParamList', ('table', T_PARAM))],
    T_PARAM: [('Flags', 'u16'), ('Sequence', 'u16'), ('Name', 'str')],
    T_INTERFACEIMPL: [('Class', ('table', T_TYPEDEF)),
                      ('Interface', 'TypeDefOrRef')],
    T_MEMBERREF: [('Class', 'MemberRefParent'), ('Name', 'str'),
                  ('Signature', 'blob')],
    T_CONSTANT: [('Type', 'u8'), ('Padding', 'u8'), ('Parent', 'HasConstant'),
                 ('Value', 'blob')],
    T_CUSTOMATTRIBUTE: [('Parent', 'HasCustomAttribute'),
                        ('Type', 'CustomAttributeType'), ('Value', 'blob')],
    T_FIELDMARSHAL: [('Parent', 'HasFieldMarshal'), ('NativeType', 'blob')],
    T_DECLSECURITY: [('Action', 'u16'), ('Parent', 'HasDeclSecurity'),
                     ('PermissionSet', 'blob')],
    T_CLASSLAYOUT: [('PackingSize', 'u16'), ('ClassSize', 'u32'),
                    ('Parent', ('table', T_TYPEDEF))],
    T_FIELDLAYOUT: [('Offset', 'u32'), ('Field', ('table', T_FIELD))],
    T_STANDALONESIG: [('Signature', 'blob')],
    T_EVENTMAP: [('Parent', ('table', T_TYPEDEF)),
                 ('EventList', ('table', T_EVENT))],
    T_EVENT: [('EventFlags', 'u16'), ('Name', 'str'),
              ('EventType', 'TypeDefOrRef')],
    T_PROPERTYMAP: [('Parent', ('table', T_TYPEDEF)),
                    ('PropertyList', ('table', T_PROPERTY))],
    T_PROPERTY: [('Flags', 'u16'), ('Name', 'str'), ('Type', 'blob')],
    T_METHODSEMANTICS: [('Semantics', 'u16'),
                        ('Method', ('table', T_METHODDEF)),
                        ('Association', 'HasSemantics')],
    T_METHODIMPL: [('Class', ('table', T_TYPEDEF)),
                   ('MethodBody', 'MethodDefOrRef'),
                   ('MethodDeclaration', 'MethodDefOrRef')],
    T_MODULEREF: [('Name', 'str')],
    T_TYPESPEC: [('Signature', 'blob')],
    T_IMPLMAP: [('MappingFlags', 'u16'), ('MemberForwarded', 'MemberForwarded'),
                ('ImportName', 'str'), ('ImportScope', ('table', T_MODULEREF))],
    T_FIELDRVA: [('RVA', 'u32'), ('Field', ('table', T_FIELD))],
    T_ASSEMBLY: [('HashAlgId', 'u32'), ('MajorVersion', 'u16'),
                 ('MinorVersion', 'u16'), ('BuildNumber', 'u16'),
                 ('RevisionNumber', 'u16'), ('Flags', 'u32'),
                 ('PublicKey', 'blob'), ('Name', 'str'), ('Culture', 'str')],
    T_ASSEMBLYREF: [('MajorVersion', 'u16'), ('MinorVersion', 'u16'),
                    ('BuildNumber', 'u16'), ('RevisionNumber', 'u16'),
                    ('Flags', 'u32'), ('PublicKeyOrToken', 'blob'),
                    ('Name', 'str'), ('Culture', 'str'), ('HashValue', 'blob')],
    T_FILE: [('Flags', 'u32'), ('Name', 'str'), ('HashValue', 'blob')],
    T_EXPORTEDTYPE: [('Flags', 'u32'), ('TypeDefId', 'u32'),
                     ('TypeName', 'str'), ('TypeNamespace', 'str'),
                     ('Implementation', 'Implementation')],
    T_MANIFESTRESOURCE: [('Offset', 'u32'), ('Flags', 'u32'), ('Name', 'str'),
                         ('Implementation', 'Implementation')],
    T_NESTEDCLASS: [('NestedClass', ('table', T_TYPEDEF)),
                    ('EnclosingClass', ('table', T_TYPEDEF))],
    T_GENERICPARAM: [('Number', 'u16'), ('Flags', 'u16'),
                     ('Owner', 'TypeOrMethodDef'), ('Name', 'str')],
    T_METHODSPEC: [('Method', 'MethodDefOrRef'), ('Instantiation', 'blob')],
    T_GENERICPARAMCONSTRAINT: [('Owner', ('table', T_GENERICPARAM)),
                               ('Constraint', 'TypeDefOrRef')],
}


# --------------------------------------------------------------------------
# metadata streams
# --------------------------------------------------------------------------
class Metadata:
    """The metadata root of a .NET image."""

    def __init__(self, data):
        self.data = data
        self.streams = {}
        self._parse_root()
        self._parse_tables()
        self.strings = self.streams['#Strings'].data
        self.us = self.streams.get('#US', _Empty()).data
        self.blob = self.streams['#Blob'].data
        self._rowcache = {}
        self._cache = {}

    def _parse_root(self):
        d = self.data
        sig, _maj, _min, _res, verlen = struct.unpack_from('<IHHII', d, 0)
        if sig != 0x424A5342:
            raise ValueError('bad metadata signature %#x' % sig)
        self.runtime_version = d[16:16 + verlen].rstrip(b'\0').decode('latin1')
        p = 16 + verlen
        _flags, nstreams = struct.unpack_from('<HH', d, p)
        p += 4
        for _ in range(nstreams):
            off, size = struct.unpack_from('<II', d, p)
            p += 8
            end = d.index(b'\0', p)
            name = d[p:end].decode('latin1')
            p = (end + 1 + 3) & ~3
            self.streams[name] = _Stream(name, d[off:off + size])

    def string(self, idx):
        if not idx:
            return ''
        end = self.strings.find(b'\0', idx)
        return self.strings[idx:end].decode('utf-8', 'replace')

    def user_string(self, idx):
        """#US heap: compressed length, UTF-16LE bytes, one trailing flag byte."""
        d = self.us
        n, p = _compressed(d, idx)
        raw = d[p:p + n]
        if n % 2:
            raw = raw[:-1]
        return raw.decode('utf-16le', 'replace')

    def blob_at(self, idx):
        n, p = _compressed(self.blob, idx)
        return self.blob[p:p + n]

    # -- table layout --------------------------------------------------
    def _parse_tables(self):
        d = self.streams['#~'].data
        (_reserved, _maj, _min, heapsizes, _r2, valid, _sorted) = \
            struct.unpack_from('<IBBBBQQ', d, 0)
        p = 24
        self.heap_sizes = heapsizes
        self.str_w = 4 if heapsizes & 0x01 else 2
        self.guid_w = 4 if heapsizes & 0x02 else 2
        self.blob_w = 4 if heapsizes & 0x04 else 2
        self.rows = {}
        for t in range(64):
            if valid & (1 << t):
                self.rows[t] = struct.unpack_from('<I', d, p)[0]
                p += 4
        # coded index widths depend on row counts, so iterate to a fixed point
        self.row_size = {}
        self.table_offset = {}
        for _ in range(3):
            self.row_size = {t: self._calc_row_size(t) for t in self.rows}
            p2 = p
            self.table_offset = {}
            for t in range(64):
                if t in self.rows:
                    self.table_offset[t] = p2
                    p2 += self.rows[t] * self.row_size[t]

    def _idx_size(self, table):
        return 4 if self.rows.get(table, 0) > 0xFFFF else 2

    def _coded_size(self, name):
        maxrows = max(self.rows.get(t, 0) for t, _ in CODED[name])
        return 4 if maxrows >= (1 << (16 - CODED_BITS[name])) else 2

    def _calc_row_size(self, t):
        cols = SCHEMA.get(t)
        if cols is None:
            return 0
        size = 0
        for _name, kind in cols:
            if kind in ('u8',):
                size += 1
            elif kind == 'u16':
                size += 2
            elif kind == 'u32':
                size += 4
            elif kind == 'str':
                size += self.str_w
            elif kind == 'guid':
                size += self.guid_w
            elif kind == 'blob':
                size += self.blob_w
            elif isinstance(kind, tuple) and kind[0] == 'table':
                size += self._idx_size(kind[1])
            elif kind in CODED:
                size += self._coded_size(kind)
            else:
                raise ValueError('unknown column kind %r' % (kind,))
        return size

    def table(self, t):
        """Yield (rid, row_dict) for table `t`, cached."""
        if t in self._cache:
            yield from self._cache[t]
            return
        rows = list(self._iter_table(t))
        self._cache[t] = rows
        yield from rows

    def _iter_table(self, t):
        n = self.rows.get(t, 0)
        if not n:
            return
        cols = SCHEMA[t]
        d = self.streams['#~'].data
        base = self.table_offset[t]
        rs = self.row_size[t]
        for i in range(n):
            p = base + i * rs
            row = {}
            for cname, kind in cols:
                if kind == 'u8':
                    row[cname] = d[p]; p += 1
                elif kind == 'u16':
                    row[cname] = struct.unpack_from('<H', d, p)[0]; p += 2
                elif kind == 'u32':
                    row[cname] = struct.unpack_from('<I', d, p)[0]; p += 4
                elif kind in ('str', 'guid', 'blob'):
                    w = {'str': self.str_w, 'guid': self.guid_w,
                         'blob': self.blob_w}[kind]
                    fmt = '<I' if w == 4 else '<H'
                    row[cname] = struct.unpack_from(fmt, d, p)[0]; p += w
                elif isinstance(kind, tuple) and kind[0] == 'table':
                    w = self._idx_size(kind[1])
                    fmt = '<I' if w == 4 else '<H'
                    row[cname] = struct.unpack_from(fmt, d, p)[0]; p += w
                elif kind in CODED:
                    w = self._coded_size(kind)
                    fmt = '<I' if w == 4 else '<H'
                    raw = struct.unpack_from(fmt, d, p)[0]; p += w
                    bits = CODED_BITS[kind]
                    tag = raw & ((1 << bits) - 1)
                    opts = CODED[kind]
                    row[cname] = (opts[tag][0] if tag < len(opts) else None,
                                  raw >> bits)
                else:
                    raise ValueError(kind)
            yield i + 1, row


class _Stream:
    __slots__ = ('name', 'data')

    def __init__(self, name, data):
        self.name = name
        self.data = data


class _Empty:
    data = b''


def _compressed(d, p):
    """ECMA-335 II.23.2 compressed unsigned integer."""
    b = d[p]
    if b & 0x80 == 0:
        return b, p + 1
    if b & 0xC0 == 0x80:
        return ((b & 0x3F) << 8) | d[p + 1], p + 2
    return (((b & 0x1F) << 24) | (d[p + 1] << 16) | (d[p + 2] << 8)
            | d[p + 3]), p + 4
