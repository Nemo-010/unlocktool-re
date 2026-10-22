"""ECMA-335 II.23.2 signature decoding."""

from metadata import _compressed

ELEM_END = 0x00; ELEM_VOID = 0x01; ELEM_BOOLEAN = 0x02; ELEM_CHAR = 0x03
ELEM_I1 = 0x04; ELEM_U1 = 0x05; ELEM_I2 = 0x06; ELEM_U2 = 0x07
ELEM_I4 = 0x08; ELEM_U4 = 0x09; ELEM_I8 = 0x0a; ELEM_U8 = 0x0b
ELEM_R4 = 0x0c; ELEM_R8 = 0x0d; ELEM_STRING = 0x0e; ELEM_PTR = 0x0f
ELEM_BYREF = 0x10; ELEM_VALUETYPE = 0x11; ELEM_CLASS = 0x12; ELEM_VAR = 0x13
ELEM_ARRAY = 0x14; ELEM_GENERICINST = 0x15; ELEM_TYPEDBYREF = 0x16
ELEM_I = 0x18; ELEM_U = 0x19; ELEM_FNPTR = 0x1b; ELEM_OBJECT = 0x1c
ELEM_SZARRAY = 0x1d; ELEM_MVAR = 0x1e; ELEM_CMOD_REQD = 0x1f
ELEM_CMOD_OPT = 0x20; ELEM_INTERNAL = 0x21; ELEM_MODIFIER = 0x40
ELEM_SENTINEL = 0x41; ELEM_PINNED = 0x45

PRIM = {
    ELEM_VOID: 'void', ELEM_BOOLEAN: 'bool', ELEM_CHAR: 'char',
    ELEM_I1: 'int8', ELEM_U1: 'uint8', ELEM_I2: 'int16', ELEM_U2: 'uint16',
    ELEM_I4: 'int32', ELEM_U4: 'uint32', ELEM_I8: 'int64', ELEM_U8: 'uint64',
    ELEM_R4: 'float32', ELEM_R8: 'float64', ELEM_STRING: 'string',
    ELEM_TYPEDBYREF: 'typedref', ELEM_I: 'native int', ELEM_U: 'native uint',
    ELEM_OBJECT: 'object',
}


class SigReader:
    def __init__(self, md, data):
        self.md = md
        self.d = data
        self.p = 0

    def u8(self):
        b = self.d[self.p]
        self.p += 1
        return b

    def compressed(self):
        v, self.p = _compressed(self.d, self.p)
        return v

    def type_name(self, md):
        e = self.u8()
        if e in PRIM:
            return PRIM[e]
        if e == ELEM_PTR:
            return self.type_name(md) + '*'
        if e == ELEM_BYREF:
            return self.type_name(md) + '&'
        if e == ELEM_SZARRAY:
            return self.type_name(md) + '[]'
        if e == ELEM_ARRAY:
            inner = self.type_name(md)
            rank = self.compressed()
            for _ in range(self.compressed()):
                self.compressed()
            for _ in range(self.compressed()):
                self.compressed()
            return inner + '[' + ',' * (rank - 1) + ']'
        if e in (ELEM_CLASS, ELEM_VALUETYPE):
            return md.type_token_name(self.compressed(), coded=True)
        if e == ELEM_VAR:
            return '!' + str(self.compressed())
        if e == ELEM_MVAR:
            return '!!' + str(self.compressed())
        if e == ELEM_GENERICINST:
            kind = self.u8()
            base = md.type_token_name(self.compressed(), coded=True)
            args = [self.type_name(md) for _ in range(self.compressed())]
            return base.split('`')[0] + '<' + ', '.join(args) + '>'
        if e in (ELEM_CMOD_REQD, ELEM_CMOD_OPT):
            mod = md.type_token_name(self.compressed(), coded=True)
            return self.type_name(md) + ' modreq(' + mod + ')'
        if e == ELEM_FNPTR:
            return 'fnptr'
        if e == ELEM_PINNED:
            return self.type_name(md)
        return 'elem_%#x' % e

    def method_sig(self, md):
        conv = self.u8()
        if conv & 0x10:
            for _ in range(self.compressed()):
                self.type_name(md)
        nparams = self.compressed()
        ret = self.type_name(md)
        params = [self.type_name(md) for _ in range(nparams)]
        return {'hasthis': bool(conv & 0x20), 'ret': ret, 'params': params,
                'conv': conv}

    def field_sig(self, md):
        self.u8()
        return self.type_name(md)
