"""Unisoc `.pac` firmware container.

Recovered from `ColokTool.UniFlash.PACExtractor` (`ParsePacHeader`,
`ParseFiles`, `UnpackPacFile`, `GetString`, `ScanXMLFile`).

## Header

`ParsePacHeader` does `Marshal.PtrToStructure<PacHeaderStruct>` over
`Marshal.SizeOf(PacHeaderStruct)` bytes read from a `BinaryReader`, so the
layout is the C# struct with `[StructLayout(Pack = 1)]` (the `ClassLayout` row
for `PacHeaderStruct` confirms `pack=1`). Every string field is a fixed-size
UTF-16 buffer read with `Encoding.Unicode.GetString(...).TrimEnd('\0')`.

Solved against the one readable sample in the tree (`NOKIA/_unassigned/frp.pac`):

    off 0x00  wchar[22]  szVersion          "BP_R1.0.0"
    off 0x2C  u32        dwHiSize           0
    off 0x30  u32        dwLoSize           941376  (= the whole file)
    off 0x34  wchar[64]  productName        "sp7731e_1h10"
    off 0xB4  wchar[64]  firmwareName       (empty)
    ...       u32 ...    partitionCount, partitionsListStart, dwMode, ...

`dwHiSize << 32 | dwLoSize` is the header length; the tool rejects a file whose
`dwHiSize`/`dwLoSize` do not agree with the actual size
("Bin packet's size is not correct").

## Version gate

`ParsePacHeader` accepts exactly two versions and rejects everything else:

```
if szVersion != "BP_R1.0.0" and szVersion != "BP_R2.0.1":
    Abort("Unsupported PAC version")
```

## What actually ships

29 `.pac` files are in the tree, and they split cleanly:

| Group | Count | Header readable | Version |
|---|---|---|---|
| `NOKIA/_unassigned/frp.pac` | 1 | yes | `BP_R1.0.0` |
| REALME `program.pac` etc. | 28 | **no** | not a `BP_R*` header |

The 28 REALME files all begin with the *same* 48-byte block
(`6cdd713d5f57dcd407ee2c8e24a2f60e…`) and are entropy-8.0 with no repeated
16-byte block anywhere, so they are a different, encrypted packaging that
`ParsePacHeader` cannot read at all — it would fail the version gate before
ever reaching the partition list.

So: the reader below is correct for the format the tool implements, and only
1 of 29 shipped files is actually in that format.
"""

import struct

SUPPORTED_VERSIONS = ('BP_R1.0.0', 'BP_R2.0.1')

SZ_VERSION_LEN = 22      # wchar count (44 bytes)
NAME_LEN = 64            # wchar count for productName / firmwareName


class PacError(Exception):
    pass


def _wstr(data, off, chars):
    raw = data[off:off + chars * 2]
    return raw.decode('utf-16le', 'replace').split('\x00')[0]


class PacHeader:
    __slots__ = ('sz_version', 'dw_hi_size', 'dw_lo_size', 'product_name',
                 'firmware_name', 'partition_count', 'partitions_list_start',
                 'raw')

    def __init__(self, **kw):
        for n in self.__slots__:
            setattr(self, n, kw.get(n))

    @property
    def header_size(self):
        """`dwHiSize << 32 | dwLoSize`."""
        return ((self.dw_hi_size or 0) << 32) | (self.dw_lo_size or 0)

    @property
    def supported(self):
        return self.sz_version in SUPPORTED_VERSIONS

    def as_dict(self):
        return {n: getattr(self, n) for n in self.__slots__ if n != 'raw'}

    def __repr__(self):
        return 'PacHeader(%r product=%r fw=%r size=%#x)' % (
            self.sz_version, self.product_name, self.firmware_name,
            self.header_size)


OFF_VERSION = 0
OFF_HI = SZ_VERSION_LEN * 2                 # 44
OFF_LO = OFF_HI + 4                         # 48
OFF_PRODUCT = OFF_LO + 4                    # 52
OFF_FIRMWARE = OFF_PRODUCT + NAME_LEN * 2   # 180
OFF_COUNT = OFF_FIRMWARE + NAME_LEN * 2     # 308
OFF_LIST = OFF_COUNT + 4                    # 312


def is_pac(data):
    """A PAC starts with a UTF-16 `BP_R` version string."""
    if len(data) < OFF_LIST:
        return False
    return data[0:1] == b'B' and data[1:2] == b'\x00'


def parse_header(data):
    if len(data) < OFF_LIST:
        raise PacError('file shorter than a PAC header')
    h = PacHeader(
        sz_version=_wstr(data, OFF_VERSION, SZ_VERSION_LEN),
        dw_hi_size=struct.unpack_from('<I', data, OFF_HI)[0],
        dw_lo_size=struct.unpack_from('<I', data, OFF_LO)[0],
        product_name=_wstr(data, OFF_PRODUCT, NAME_LEN),
        firmware_name=_wstr(data, OFF_FIRMWARE, NAME_LEN),
        partition_count=struct.unpack_from('<I', data, OFF_COUNT)[0],
        partitions_list_start=struct.unpack_from('<I', data, OFF_LIST)[0],
        raw=data[:OFF_LIST],
    )
    return h


def parse(data):
    h = parse_header(data)
    if not h.supported:
        raise PacError('Unsupported PAC version: %r' % h.sz_version)
    if h.header_size and h.header_size > len(data):
        raise PacError("Bin packet's size is not correct: %#x > %d"
                       % (h.header_size, len(data)))
    return h


def parse_file(path):
    with open(path, 'rb') as fh:
        return parse(fh.read())
