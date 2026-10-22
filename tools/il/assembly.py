"""PE + metadata + IL facade for one managed assembly."""

import struct

from metadata import (Metadata, T_ASSEMBLY, T_ASSEMBLYREF, T_FIELD,
                      T_FIELDRVA, T_IMPLMAP, T_MEMBERREF, T_METHODDEF,
                      T_MODULEREF, T_PARAM, T_TYPEDEF, T_TYPEREF, T_TYPESPEC,
                      T_MANIFESTRESOURCE)
from signatures import SigReader


class Assembly:
    def __init__(self, path):
        with open(path, 'rb') as fh:
            self.raw = fh.read()
        self.path = path
        self._parse_pe()
        self.md = Metadata(self._md_blob())
        self._tidx = None
        self._mown = None

    # -- PE ------------------------------------------------------------
    def _parse_pe(self):
        raw = self.raw
        pe = struct.unpack_from('<I', raw, 0x3C)[0]
        nsec = struct.unpack_from('<H', raw, pe + 6)[0]
        optsz = struct.unpack_from('<H', raw, pe + 20)[0]
        opt = pe + 24
        self.image_base = struct.unpack_from('<I', raw, opt + 28)[0]
        self.sections = []
        so = opt + optsz
        for i in range(nsec):
            o = so + 40 * i
            name = raw[o:o + 8].rstrip(b'\0').decode('latin1')
            vs, va, rs, ra = struct.unpack_from('<IIII', raw, o + 8)
            self.sections.append((name, va, vs, ra, rs))
        self.cli_rva, self.cli_size = struct.unpack_from('<II', raw, opt + 96 + 14 * 8)

    def rva2off(self, rva):
        for _name, va, vs, ra, rs in self.sections:
            if va <= rva < va + max(vs, rs):
                return ra + (rva - va)
        raise ValueError('rva %#x not mapped' % rva)

    def _md_blob(self):
        off = self.rva2off(self.cli_rva)
        _cb, _mj, _mn, md_rva, md_size = struct.unpack_from('<IHHII', self.raw, off)
        mdoff = self.rva2off(md_rva)
        return self.raw[mdoff:mdoff + md_size]

    # -- row access ----------------------------------------------------
    @staticmethod
    def row(md, table, rid):
        for i, r in md.table(table):
            if i == rid:
                return r
        raise KeyError('no row %d in table %d' % (rid, table))

    # -- name resolution ------------------------------------------------
    def type_token_name(self, tok, coded=False):
        md = self.md
        if coded:
            tag = tok & 3
            rid = tok >> 2
            table = {0: T_TYPEDEF, 1: T_TYPEREF, 2: T_TYPESPEC}.get(tag)
        else:
            table = tok & 0xFF000000
            rid = tok & 0x00FFFFFF
            table = {0x02000000: T_TYPEDEF, 0x01000000: T_TYPEREF,
                     0x1B000000: T_TYPESPEC}.get(table)
        if table == T_TYPEDEF or table == T_TYPEREF:
            r = self.row(md, table, rid)
            ns = md.string(r['Namespace'])
            n = md.string(r['Name'])
            return (ns + '.' + n) if ns else n
        if table == T_TYPESPEC:
            r = self.row(md, T_TYPESPEC, rid)
            return SigReader(md, md.blob_at(r['Signature'])).type_name(self)
        return 'tok_%08x' % tok

    def token_repr(self, tok):
        md = self.md
        table = tok & 0xFF000000
        rid = tok & 0x00FFFFFF
        if table == 0x0A000000:                     # MemberRef
            r = self.row(md, T_MEMBERREF, rid)
            name = md.string(r['Name'])
            pt, prid = r['Class']
            if pt == T_TYPESPEC:
                sr = self.row(md, T_TYPESPEC, prid)
                parent = SigReader(md, md.blob_at(sr['Signature'])).type_name(self)
            elif pt in (T_TYPEREF, T_TYPEDEF):
                pr = self.row(md, pt, prid)
                ns = md.string(pr['Namespace'])
                pn = md.string(pr['Name'])
                parent = (ns + '.' + pn) if ns else pn
            elif pt == T_METHODDEF:
                parent = self.method_full_name(prid)
            else:
                parent = 'modref'
            return parent + '::' + name
        if table == 0x06000000:
            return self.method_full_name(rid)
        if table in (0x01000000, 0x02000000, 0x1B000000):
            return self.type_token_name(tok)
        if table == 0x04000000:
            return 'field:' + md.string(self.row(md, T_FIELD, rid)['Name'])
        if table == 0x70000000:
            return md.user_string(rid)
        return 'tok_%08x' % tok

    # -- type/method index ---------------------------------------------
    def _type_index(self):
        if self._tidx is None:
            md = self.md
            types = list(md.table(T_TYPEDEF))
            nmeth = md.rows.get(T_METHODDEF, 0)
            nfield = md.rows.get(T_FIELD, 0)
            idx = {}
            for i, (trid, r) in enumerate(types):
                mstart = r['MethodList']
                mend = types[i + 1][1]['MethodList'] if i + 1 < len(types) else nmeth + 1
                fstart = r['FieldList']
                fend = types[i + 1][1]['FieldList'] if i + 1 < len(types) else nfield + 1
                idx[trid] = (mstart, mend, fstart, fend)
            self._tidx = idx
        return self._tidx

    def type_methods(self, rid):
        e = self._type_index().get(rid)
        if not e:
            return []
        n = self.md.rows.get(T_METHODDEF, 0)
        return [m for m in range(e[0], e[1]) if m <= n]

    def type_fields(self, rid):
        e = self._type_index().get(rid)
        if not e:
            return []
        n = self.md.rows.get(T_FIELD, 0)
        return [f for f in range(e[2], e[3]) if f <= n]

    def _method_owner(self):
        if self._mown is None:
            md = self.md
            types = list(md.table(T_TYPEDEF))
            nmeth = md.rows.get(T_METHODDEF, 0)
            own = {}
            for i, (trid, r) in enumerate(types):
                start = r['MethodList']
                end = types[i + 1][1]['MethodList'] if i + 1 < len(types) else nmeth + 1
                ns = md.string(r['Namespace'])
                n = md.string(r['Name'])
                full = (ns + '.' + n) if ns else n
                for m in range(start, min(end, nmeth + 1)):
                    own[m] = full
            self._mown = own
        return self._mown

    def method_full_name(self, rid):
        owner = self._method_owner().get(rid)
        name = self.md.string(self.row(self.md, T_METHODDEF, rid)['Name'])
        return (owner + '::' if owner else '') + name

    def method_sig(self, rid):
        r = self.row(self.md, T_METHODDEF, rid)
        return SigReader(self.md, self.md.blob_at(r['Signature'])).method_sig(self)

    def method_params(self, rid):
        md = self.md
        r = self.row(md, T_METHODDEF, rid)
        n = md.rows.get(T_PARAM, 0)
        nxt = self.row(md, T_METHODDEF, rid + 1)['ParamList'] \
            if rid < md.rows.get(T_METHODDEF, 0) else n + 1
        out = []
        for prid in range(r['ParamList'], nxt):
            if prid > n:
                break
            pr = self.row(md, T_PARAM, prid)
            out.append((md.string(pr['Name']), pr['Sequence']))
        return out

    def body(self, rid):
        r = self.row(self.md, T_METHODDEF, rid)
        if not r['RVA']:
            return None
        off = self.rva2off(r['RVA'])
        b = self.raw[off]
        if b & 3 == 2:                          # tiny header
            size = b >> 2
            return self.raw[off + 1:off + 1 + size]
        flags_size, _maxstack, codesize, _lv = struct.unpack_from('<HHII', self.raw, off)
        hdr = (flags_size >> 12) * 4
        return self.raw[off + hdr:off + hdr + codesize]

    # -- convenience views ---------------------------------------------
    def types(self):
        for rid, r in self.md.table(T_TYPEDEF):
            ns = self.md.string(r['Namespace'])
            n = self.md.string(r['Name'])
            yield rid, ns, n, r

    def find_type(self, name):
        for rid, ns, n, _r in self.types():
            full = (ns + '.' + n) if ns else n
            if full == name or n == name:
                return rid
        return None

    def assembly_refs(self):
        return [self.md.string(r['Name'])
                for _rid, r in self.md.table(T_ASSEMBLYREF)]

    def assembly_name(self):
        for _rid, r in self.md.table(T_ASSEMBLY):
            return self.md.string(r['Name'])
        return None

    def module_refs(self):
        return {rid: self.md.string(r['Name'])
                for rid, r in self.md.table(T_MODULEREF)}

    def pinvokes(self):
        """[(module, entrypoint, owning type::method)] for every ImplMap row."""
        md = self.md
        mods = self.module_refs()
        own = self._method_owner()
        out = []
        for _rid, r in md.table(T_IMPLMAP):
            t, ref = r['MemberForwarded']
            scope = mods.get(r['ImportScope'], '?')
            entry = md.string(r['ImportName'])
            if t == T_METHODDEF:
                who = '%s::%s' % (own.get(ref, '?'),
                                  md.string(self.row(md, T_METHODDEF, ref)['Name']))
            else:
                who = 'field#%d' % ref
            out.append((scope, entry, who))
        return out

    def field_rva_arrays(self):
        """[(field name, bytes)] for every FieldRVA-initialised field."""
        md = self.md
        out = []
        for _rid, r in md.table(T_FIELDRVA):
            f = self.row(md, T_FIELD, r['Field'])
            off = self.rva2off(r['RVA'])
            out.append((md.string(f['Name']), self.raw[off:off + 4096]))
        return out

    def manifest_resources(self):
        return [(self.md.string(r['Name']), r['Offset'], r['Flags'])
                for _rid, r in self.md.table(T_MANIFESTRESOURCE)]
