"""The `MotoKingProS` container: a fifth vendor's blob in the merged tree.

Found in the 40 large `_auth_sv5.auth` files (1 049 756 bytes each).  Layout,
recovered by inspection:

    off 0x00  12 bytes  magic      "MotoKingProS" or "MotoKingProR"
    off 0x0c  u32be     version    4
    off 0x10  u32be     field      0x224D1840
    off 0x14  u32be     field      0x40C04400
    off 0x18  u32be     field      0x0000F017
    off 0x1c  base64    filename   NUL-terminated, e.g.
                                   "SM-A155F.B5.mt6789_auth_sv5." (with the
                                   extension cut off mid-encode, so the string
                                   is truncated at a NUL and the last group is
                                   padded by hand)
    then                payload    opaque, high-entropy
    tail      4 bytes   0x00000000

The filename field is base64 of the *original* file name, which is how these
blobs stayed attributable after being renamed to `auth.auth` / `_auth_sv5.auth`
by the merge.  Decoding it recovers the source model and chipset.

This is a *different vendor's* container from the `0x844BDCD1` pre-loader
(`container.py`) and from ColokTool's AES-wrapped `programs.bin`.  It is never
read by `ColokTool.exe`; it exists because `data/` is a merge (see
`docs/data-layouts.md`).
"""

import base64
import re
import struct

MAGIC = b'MotoKingProS'
# Two variants ship in the tree; the trailing letter is a format revision.
MAGICS = (b'MotoKingProS', b'MotoKingProR')
HEADER_MIN = 0x1C
# The base64 run is alphanumeric plus +/ and is terminated by a NUL or a byte
# outside the alphabet.  It is *not* necessarily a whole number of groups.
_B64 = re.compile(rb'[A-Za-z0-9+/]{8,}')


class MotoKingError(Exception):
    pass


def is_container(data):
    return data[:12] in MAGICS


class MotoKingBlob:
    __slots__ = ('magic', 'version', 'fields', 'name_b64', 'name', 'payload',
                 'tail')

    def __init__(self, **kw):
        for n in self.__slots__:
            setattr(self, n, kw.get(n))

    def as_dict(self):
        return {'magic': self.magic, 'version': self.version,
                'fields': self.fields, 'name_b64': self.name_b64,
                'name': self.name, 'payload_len': len(self.payload or b''),
                'tail': self.tail.hex() if self.tail else None}

    def __repr__(self):
        return 'MotoKingBlob(v%d name=%r payload=%d)' % (
            self.version or 0, self.name, len(self.payload or b''))


def _decode_name(raw):
    """Recover the original filename from the truncated base64 field."""
    pad = raw + b'=' * (-len(raw) % 4)
    try:
        return base64.b64decode(pad, validate=False)
    except Exception:                       # noqa: BLE001 - best effort
        return b''


def parse(data):
    if not is_container(data):
        raise MotoKingError('not a MotoKingProS blob')
    if len(data) < HEADER_MIN:
        raise MotoKingError('truncated header')
    # the header integers are big-endian
    magic = data[:12]
    version, = struct.unpack_from('>I', data, 0x0C)
    fields = struct.unpack_from('>III', data, 0x10)
    m = _B64.search(data, HEADER_MIN)
    if not m:
        raise MotoKingError('no base64 filename field')
    raw_name = m.group(0)
    name = _decode_name(raw_name)
    payload_start = m.end()
    # The name field is followed by a fixed 6-byte marker, then the payload:
    #   0C 00 '?' 'g' '=' 00
    if data[payload_start:payload_start + 6] == b'\x0c\x00?g=\x00':
        payload_start += 6
    while payload_start < len(data) and data[payload_start] == 0x00:
        payload_start += 1
    tail = data[-4:]
    payload = data[payload_start:len(data) - 4]
    return MotoKingBlob(magic=magic, version=version, fields=fields,
                        name_b64=raw_name, name=name.decode('latin1'),
                        payload=payload, tail=tail)


def build(name, payload, version=4, fields=(0x224D1840, 0x40C04400, 0x0000F017)):
    """Emit a blob `parse` accepts — used by the round-trip test."""
    b64 = base64.b64encode(name.encode('latin1'))[:40]
    hdr = MAGIC + struct.pack('>I', version) + struct.pack('>III', *fields)
    hdr += b64 + b'\x0c\x00?g=\x00'
    return hdr + payload + b'\x00\x00\x00\x00'
