"""OPPO `.ofp` firmware container reader.

Recovered from `ColokTool.OFPExtractor` (`GetXml`, `Unpack`, `HexToDec`,
`bulat`).  The layout, in the order the IL reads it:

```
seek(file_length + 16 - page_size)
read 4 bytes -> hex -> ToLower -> Contains("ef7c")   ; the page-size probe
```

Note the probe compares the **raw** hex; it does *not* go through `Unpack`.
`GetXml` tries `page_size = 512` first and `4096` second, and accepts whichever
probe matches.  Then:

```
page_size        = 512 or 4096
base             = file_length - page_size
seek(base + 20); read u32 -> Unpack -> HexToDec -> * page_size   = xml_offset
seek(...);       read u32 -> Unpack -> HexToDec                  = xml_size
xml              = read(xml_offset, ceil(xml_size/16)*16)
```

Two details that are easy to get wrong:

1. `Unpack(string hex)` does **not** decode hex — it reverses the *byte-pair*
   order. It splits the hex string into 2-character groups, then concatenates
   them back to front. So for the 4 bytes `01 02 03 04` → `"01020304"` →
   `"04030201"`.
2. `HexToDec(string)` is literally `Val("&H" + s)` — a hex parse, with no
   endianness handling of its own. The endianness comes entirely from
   `Unpack`'s reversal, so the stored integers are **little-endian**: bytes
   `01 00 00 00` -> hex `"01000000"` -> reversed `"00000001"` -> 1.

The XML is then walked by `BruteKeyQcom` / `decryptFile` for the per-partition
entries.

No `.ofp` file ships in the archive, so this reader is exercised only against
synthetic fixtures built to the same rules.  It is marked **simulated** in
`docs/validation-report.md` accordingly.
"""

import math
import struct

PROBE_MARKER = 'ef7c'
PAGE_SIZES = (512, 4096)


class OfpError(Exception):
    pass


def unpack(hex_text):
    """`OFPExtractor.Unpack`: reverse the 2-char group order."""
    groups = [hex_text[i:i + 2] for i in range(0, len(hex_text) - 1, 2)]
    return ''.join(reversed(groups))


def hex_to_dec(text):
    """`OFPExtractor.HexToDec`: Val("&H" + text)."""
    try:
        return int(text, 16)
    except (TypeError, ValueError):
        raise OfpError('not a hex integer: %r' % (text,))


def read_uint_le(data, offset):
    """Read a u32 the way the tool does: hex -> Unpack -> HexToDec.

    The net effect is little-endian, because `Unpack` reverses the byte pairs.
    """
    raw = data[offset:offset + 4]
    if len(raw) != 4:
        raise OfpError('short read at %#x' % offset)
    return hex_to_dec(unpack(raw.hex()))


def ceil16(n):
    """`bulat(n/16)*16 - 1 + 1`, i.e. round up to a 16-byte multiple."""
    return int(math.ceil(n / 16.0)) * 16


class OfpFile:
    __slots__ = ('path', 'size', 'page_size', 'xml_offset', 'xml_size', 'xml')

    def __init__(self, **kw):
        for n in self.__slots__:
            setattr(self, n, kw.get(n))

    def __repr__(self):
        return 'OfpFile(size=%d page=%s xml=%#x+%#x)' % (
            self.size or 0, self.page_size, self.xml_offset or 0,
            self.xml_size or 0)


def detect_page_size(data):
    """Reproduce the probe loop in `GetXml`.

    Note the probe compares the **raw** hex of the 4 bytes read at
    `file_length + 16 - page_size` against "ef7c" — it does not go through
    `Unpack` first.  (The IL at IL_0076..IL_0086 is BytesToHextring ->
    ToLower -> Contains("ef7c"), with no Unpack call.)
    """
    size = len(data)
    for page in PAGE_SIZES:
        probe = size + 16 - page
        if probe < 0:
            continue
        raw = data[probe:probe + 4]
        if len(raw) != 4:
            continue
        if PROBE_MARKER in raw.hex().lower():
            return page
    return None


def parse(data, path=None):
    size = len(data)
    page = detect_page_size(data)
    if page is None:
        raise OfpError('no page-size probe matched (not an .ofp?)')
    base = size - page
    xml_offset = read_uint_le(data, base + 20) * page
    xml_size = read_uint_le(data, base + 24)
    if xml_offset <= 0 or xml_offset >= size:
        raise OfpError('xml offset %#x outside the file' % xml_offset)
    n = ceil16(xml_size)
    blob = data[xml_offset:xml_offset + n]
    if not blob:
        raise OfpError('empty xml region')
    return OfpFile(path=path, size=size, page_size=page,
                   xml_offset=xml_offset, xml_size=xml_size, xml=blob)


def parse_file(path):
    with open(path, 'rb') as fh:
        return parse(fh.read(), path)


# --- fixture builder -------------------------------------------------------

def build(xml_bytes, page_size=512, size=None):
    """Emit a minimal container that `parse` accepts.

    `size` lets a caller choose the total file length; by default it is large
    enough to hold the XML with room for the footer.
    """
    xml_len = ceil16(len(xml_bytes))
    total = size or (xml_len + page_size * 4)
    buf = bytearray(total)
    # the XML region, at page_size (one page in)
    xml_offset = page_size
    buf[xml_offset:xml_offset + len(xml_bytes)] = xml_bytes
    base = total - page_size

    def put_le_u32(off, value):
        buf[off:off + 4] = struct.pack('<I', value)

    put_le_u32(base + 20, xml_offset // page_size)
    put_le_u32(base + 24, len(xml_bytes))
    # the probe: 4 bytes whose raw hex contains 'ef7c'
    probe = total + 16 - page_size
    buf[probe:probe + 4] = bytes.fromhex('00ef7c00')
    return bytes(buf)
