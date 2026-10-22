"""ECMA-335 III instruction table and a disassembler."""

import struct

_TABLE = [
    (0x00, 'nop', None), (0x01, 'break', None),
    (0x02, 'ldarg.0', None), (0x03, 'ldarg.1', None), (0x04, 'ldarg.2', None),
    (0x05, 'ldarg.3', None), (0x06, 'ldloc.0', None), (0x07, 'ldloc.1', None),
    (0x08, 'ldloc.2', None), (0x09, 'ldloc.3', None), (0x0A, 'stloc.0', None),
    (0x0B, 'stloc.1', None), (0x0C, 'stloc.2', None), (0x0D, 'stloc.3', None),
    (0x0E, 'ldarg.s', 'VarS'), (0x0F, 'ldarga.s', 'VarS'),
    (0x10, 'starg.s', 'VarS'), (0x11, 'ldloc.s', 'VarS'),
    (0x12, 'ldloca.s', 'VarS'), (0x13, 'stloc.s', 'VarS'),
    (0x14, 'ldnull', None), (0x15, 'ldc.i4.m1', None),
    (0x16, 'ldc.i4.0', None), (0x17, 'ldc.i4.1', None), (0x18, 'ldc.i4.2', None),
    (0x19, 'ldc.i4.3', None), (0x1A, 'ldc.i4.4', None), (0x1B, 'ldc.i4.5', None),
    (0x1C, 'ldc.i4.6', None), (0x1D, 'ldc.i4.7', None), (0x1E, 'ldc.i4.8', None),
    (0x1F, 'ldc.i4.s', 'I1'), (0x20, 'ldc.i4', 'I4'), (0x21, 'ldc.i8', 'I8'),
    (0x22, 'ldc.r4', 'R4'), (0x23, 'ldc.r8', 'R8'),
    (0x25, 'dup', None), (0x26, 'pop', None),
    (0x27, 'jmp', 'Tok'), (0x28, 'call', 'Tok'), (0x29, 'calli', 'Tok'),
    (0x2A, 'ret', None),
    (0x2B, 'br.s', 'BrS'), (0x2C, 'brfalse.s', 'BrS'), (0x2D, 'brtrue.s', 'BrS'),
    (0x2E, 'beq.s', 'BrS'), (0x2F, 'bge.s', 'BrS'), (0x30, 'bgt.s', 'BrS'),
    (0x31, 'ble.s', 'BrS'), (0x32, 'blt.s', 'BrS'), (0x33, 'bne.un.s', 'BrS'),
    (0x34, 'bge.un.s', 'BrS'), (0x35, 'bgt.un.s', 'BrS'),
    (0x36, 'ble.un.s', 'BrS'), (0x37, 'blt.un.s', 'BrS'),
    (0x38, 'br', 'Br'), (0x39, 'brfalse', 'Br'), (0x3A, 'brtrue', 'Br'),
    (0x3B, 'beq', 'Br'), (0x3C, 'bge', 'Br'), (0x3D, 'bgt', 'Br'),
    (0x3E, 'ble', 'Br'), (0x3F, 'blt', 'Br'), (0x40, 'bne.un', 'Br'),
    (0x41, 'bge.un', 'Br'), (0x42, 'bgt.un', 'Br'), (0x43, 'ble.un', 'Br'),
    (0x44, 'blt.un', 'Br'), (0x45, 'switch', 'Sw'),
    (0x46, 'ldind.i1', None), (0x47, 'ldind.u1', None), (0x48, 'ldind.i2', None),
    (0x49, 'ldind.u2', None), (0x4A, 'ldind.i4', None), (0x4B, 'ldind.u4', None),
    (0x4C, 'ldind.i8', None), (0x4D, 'ldind.i', None), (0x4E, 'ldind.r4', None),
    (0x4F, 'ldind.r8', None), (0x50, 'ldind.ref', None),
    (0x51, 'stind.ref', None), (0x52, 'stind.i1', None), (0x53, 'stind.i2', None),
    (0x54, 'stind.i4', None), (0x55, 'stind.i8', None), (0x56, 'stind.r4', None),
    (0x57, 'stind.r8', None),
    (0x58, 'add', None), (0x59, 'sub', None), (0x5A, 'mul', None),
    (0x5B, 'div', None), (0x5C, 'div.un', None), (0x5D, 'rem', None),
    (0x5E, 'rem.un', None), (0x5F, 'and', None), (0x60, 'or', None),
    (0x61, 'xor', None), (0x62, 'shl', None), (0x63, 'shr', None),
    (0x64, 'shr.un', None), (0x65, 'neg', None), (0x66, 'not', None),
    (0x67, 'conv.i1', None), (0x68, 'conv.i2', None), (0x69, 'conv.i4', None),
    (0x6A, 'conv.i8', None), (0x6B, 'conv.r4', None), (0x6C, 'conv.r8', None),
    (0x6D, 'conv.u4', None), (0x6E, 'conv.u8', None),
    (0x6F, 'callvirt', 'Tok'), (0x70, 'cpobj', 'Tok'), (0x71, 'ldobj', 'Tok'),
    (0x72, 'ldstr', 'Str'), (0x73, 'newobj', 'Tok'), (0x74, 'castclass', 'Tok'),
    (0x75, 'isinst', 'Tok'), (0x76, 'conv.r.un', None),
    (0x79, 'unbox', 'Tok'), (0x7A, 'throw', None),
    (0x7B, 'ldfld', 'Tok'), (0x7C, 'ldflda', 'Tok'), (0x7D, 'stfld', 'Tok'),
    (0x7E, 'ldsfld', 'Tok'), (0x7F, 'ldsflda', 'Tok'), (0x80, 'stsfld', 'Tok'),
    (0x81, 'stobj', 'Tok'),
    (0x82, 'conv.ovf.i1.un', None), (0x83, 'conv.ovf.i2.un', None),
    (0x84, 'conv.ovf.i4.un', None), (0x85, 'conv.ovf.i8.un', None),
    (0x86, 'conv.ovf.u1.un', None), (0x87, 'conv.ovf.u2.un', None),
    (0x88, 'conv.ovf.u4.un', None), (0x89, 'conv.ovf.u8.un', None),
    (0x8A, 'conv.ovf.i.un', None), (0x8B, 'conv.ovf.u.un', None),
    (0x8C, 'box', 'Tok'), (0x8D, 'newarr', 'Tok'), (0x8E, 'ldlen', None),
    (0x8F, 'ldelema', 'Tok'),
    (0x90, 'ldelem.i1', None), (0x91, 'ldelem.u1', None),
    (0x92, 'ldelem.i2', None), (0x93, 'ldelem.u2', None),
    (0x94, 'ldelem.i4', None), (0x95, 'ldelem.u4', None),
    (0x96, 'ldelem.i8', None), (0x97, 'ldelem.i', None),
    (0x98, 'ldelem.r4', None), (0x99, 'ldelem.r8', None),
    (0x9A, 'ldelem.ref', None),
    (0x9B, 'stelem.i', None), (0x9C, 'stelem.i1', None),
    (0x9D, 'stelem.i2', None), (0x9E, 'stelem.i4', None),
    (0x9F, 'stelem.i8', None), (0xA0, 'stelem.r4', None),
    (0xA1, 'stelem.r8', None), (0xA2, 'stelem.ref', None),
    (0xA3, 'ldelem', 'Tok'), (0xA4, 'stelem', 'Tok'), (0xA5, 'unbox.any', 'Tok'),
    (0xB3, 'conv.ovf.i1', None), (0xB4, 'conv.ovf.u1', None),
    (0xB5, 'conv.ovf.i2', None), (0xB6, 'conv.ovf.u2', None),
    (0xB7, 'conv.ovf.i4', None), (0xB8, 'conv.ovf.u4', None),
    (0xB9, 'conv.ovf.i8', None), (0xBA, 'conv.ovf.u8', None),
    (0xC2, 'refanyval', 'Tok'), (0xC3, 'ckfinite', None),
    (0xC6, 'mkrefany', 'Tok'), (0xD0, 'ldtoken', 'Tok'),
    (0xD1, 'conv.u2', None), (0xD2, 'conv.u1', None), (0xD3, 'conv.i', None),
    (0xD4, 'conv.ovf.i', None), (0xD5, 'conv.ovf.u', None),
    (0xD6, 'add.ovf', None), (0xD7, 'add.ovf.un', None),
    (0xD8, 'mul.ovf', None), (0xD9, 'mul.ovf.un', None),
    (0xDA, 'sub.ovf', None), (0xDB, 'sub.ovf.un', None),
    (0xDC, 'endfinally', None), (0xDD, 'leave', 'Br'), (0xDE, 'leave.s', 'BrS'),
    (0xDF, 'stind.i', None), (0xE0, 'conv.u', None),
    (0xFE00, 'arglist', None), (0xFE01, 'ceq', None), (0xFE02, 'cgt', None),
    (0xFE03, 'cgt.un', None), (0xFE04, 'clt', None), (0xFE05, 'clt.un', None),
    (0xFE06, 'ldftn', 'Tok'), (0xFE07, 'ldvirtftn', 'Tok'),
    (0xFE09, 'ldarg', 'Var'), (0xFE0A, 'ldarga', 'Var'),
    (0xFE0B, 'starg', 'Var'), (0xFE0C, 'ldloc', 'Var'),
    (0xFE0D, 'ldloca', 'Var'), (0xFE0E, 'stloc', 'Var'),
    (0xFE0F, 'localloc', None), (0xFE11, 'endfilter', None),
    (0xFE12, 'unaligned.', 'U1'), (0xFE13, 'volatile.', None),
    (0xFE14, 'tail.', None), (0xFE15, 'initobj', 'Tok'),
    (0xFE16, 'constrained.', 'Tok'), (0xFE17, 'cpblk', None),
    (0xFE18, 'initblk', None), (0xFE19, 'no.', 'U1'), (0xFE1A, 'rethrow', None),
    (0xFE1C, 'sizeof', 'Tok'), (0xFE1D, 'refanytype', None),
    (0xFE1E, 'readonly.', None),
]

OPS = {op: (name, kind) for op, name, kind in _TABLE}
OPS[0xE6] = ('ldftn', 'Tok')
OPS[0xE7] = ('ldvirtftn', 'Tok')
OPS[0xE8] = ('ldarg', 'Var')
OPS[0xEA] = ('starg', 'Var')
OPS[0xEC] = ('ldloc', 'Var')
OPS[0xEE] = ('stloc', 'Var')


def disassemble(asm, code):
    """Return [(offset, name, operand_text, raw_bytes)]."""
    out = []
    p = 0
    n = len(code)
    while p < n:
        start = p
        b = code[p]
        p += 1
        if b == 0xFE:
            if p >= n:
                out.append((start, 'truncated_FE', '', code[start:]))
                break
            op = 0xFE00 | code[p]
            p += 1
        else:
            op = b
        ent = OPS.get(op)
        if ent is None:
            out.append((start, 'unknown_%02x' % op, '', code[start:p]))
            continue
        name, kind = ent
        try:
            if kind is None:
                text = ''
            elif kind == 'I1':
                text = str(struct.unpack_from('<b', code, p)[0]); p += 1
            elif kind == 'U1':
                text = str(code[p]); p += 1
            elif kind == 'I4':
                text = str(struct.unpack_from('<i', code, p)[0]); p += 4
            elif kind == 'I8':
                text = str(struct.unpack_from('<q', code, p)[0]); p += 8
            elif kind == 'R4':
                text = repr(struct.unpack_from('<f', code, p)[0]); p += 4
            elif kind == 'R8':
                text = repr(struct.unpack_from('<d', code, p)[0]); p += 8
            elif kind == 'Br':
                v = struct.unpack_from('<i', code, p)[0]; p += 4
                text = 'IL_%04X' % (p + v)
            elif kind == 'BrS':
                v = struct.unpack_from('<b', code, p)[0]; p += 1
                text = 'IL_%04X' % (p + v)
            elif kind == 'Sw':
                cnt = struct.unpack_from('<I', code, p)[0]; p += 4
                t = []
                for _ in range(cnt):
                    v = struct.unpack_from('<i', code, p)[0]; p += 4
                    t.append(p + v)
                text = '[' + ', '.join('IL_%04X' % x for x in t) + ']'
            elif kind == 'Var':
                text = str(struct.unpack_from('<H', code, p)[0]); p += 2
            elif kind == 'VarS':
                text = str(code[p]); p += 1
            elif kind == 'Str':
                tok = struct.unpack_from('<I', code, p)[0]; p += 4
                s = asm.md.user_string(tok & 0x00FFFFFF)
                text = '"' + (s.replace('\\', '\\\\').replace('"', '\\"')
                              .replace('\r', '\\r').replace('\n', '\\n')
                              .replace('\t', '\\t')) + '"'
            elif kind == 'Tok':
                tok = struct.unpack_from('<I', code, p)[0]; p += 4
                text = asm.token_repr(tok)
            else:
                text = ''
        except (IndexError, struct.error):
            out.append((start, name, '<truncated>', code[start:]))
            break
        out.append((start, name, text, code[start:p]))
    return out
