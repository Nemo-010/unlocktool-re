"""Inno Setup 6.7.0 container reader (the tool's outer packaging).

Everything here is derived from jrsoftware/issrc at tag `is-6_7_0`:

  Projects/Src/Shared.Struct.pas          TSetupHeader, TSetupFileEntry,
                                          TSetupFileLocationEntry, TSetupEncryptionHeader
  Projects/Src/Compression.Base.pas       TCompressedBlockWriter / TCompressedBlockReader
  Projects/Src/Shared.SetupEntFunc.pas    SECompressedBlockWrite ordering
  Projects/Src/Shared.Struct.pas          TSetupLdrOffsetTable (resource 11111)
  Projects/Src/Compression.Base.pas       TransformCallInstructions()

The archive we were given is a 7z containing a single Inno Setup installer
plus a PNG.  This module reads the installer, not the 7z.
"""

import lzma
import struct
import zlib

INNO_MAGIC_LOADER = 0x6F6E6E49          # "Inno" at file offset 0x30
RES_ID_OFFSET_TABLE = 11111
OFFSET_TABLE_ID = b'rDlPtS\xcd\xe6\xd7{\x0b\x2a'

BLOCK_CHUNK = 4096


class InnoFormatError(Exception):
    pass


class ChunkSource:
    """Random-access view over a file that may be split into pieces.

    The installer in this task is 2.3 GB; it had to be downloaded in two
    ranged HTTP requests, so `pieces` is [(path, start_offset), ...].
    """

    def __init__(self, pieces=()):
        # pieces: [(path, start_offset, length), ...]
        self.pieces = list(pieces)
        self.size = max((p[1] + p[2] for p in self.pieces), default=0)
        self._fds = {}

    @classmethod
    def from_paths(cls, paths):
        import os
        src = cls()
        off = 0
        for p in paths:
            n = os.path.getsize(p)
            src.pieces.append((p, off, n))
            off += n
        src.size = off
        return src

    def _fd(self, path):
        fd = self._fds.get(path)
        if fd is None:
            fd = open(path, 'rb')
            self._fds[path] = fd
        return fd

    def read(self, off, n):
        if off < 0 or n < 0:
            raise ValueError('negative read')
        out = bytearray()
        for path, start, length in self.pieces:
            if off + n <= start or off >= start + length:
                continue
            a = max(off, start)
            b = min(off + n, start + length)
            fd = self._fd(path)
            fd.seek(a - start)
            out += fd.read(b - a)
        return bytes(out)

    def close(self):
        for fd in self._fds.values():
            fd.close()
        self._fds.clear()


# --------------------------------------------------------------------------
# PE / resource helpers
# --------------------------------------------------------------------------

def _pe_sections(raw):
    pe = struct.unpack_from('<I', raw, 0x3C)[0]
    nsec = struct.unpack_from('<H', raw, pe + 6)[0]
    optsz = struct.unpack_from('<H', raw, pe + 20)[0]
    opt = pe + 24
    sections = []
    so = opt + optsz
    for i in range(nsec):
        o = so + 40 * i
        name = raw[o:o + 8].rstrip(b'\0').decode('latin1')
        vs, va, rs, ra = struct.unpack_from('<IIII', raw, o + 8)
        sections.append((name, va, vs, ra, rs))
    return sections


def _rva2off(sections, rva):
    for name, va, vs, ra, rs in sections:
        if va <= rva < va + max(vs, rs):
            return ra + (rva - va)
    return None


def find_loader_offset_table(src):
    """Locate TSetupLdrOffsetTable.

    Two storage methods exist (loader/offsets.cpp in innoextract mirrors the
    same logic): a pointer at file offset 0x30 for Inno < 5.1.5, or an RCDATA
    resource with id 11111 for newer versions.  This installer uses the
    resource form.
    """
    head = src.read(0, 0x400)
    sections = _pe_sections(head)
    pe = struct.unpack_from('<I', head, 0x3C)[0]
    optsz = struct.unpack_from('<H', head, pe + 20)[0]
    opt = pe + 24
    # data directory index 2 is the resource table
    rsrc_rva = struct.unpack_from('<I', head, opt + 96 + 2 * 8)[0]
    if not rsrc_rva:
        raise InnoFormatError('no resource directory')
    base = _rva2off(sections, rsrc_rva)
    if base is None:
        raise InnoFormatError('resource directory not mapped')
    return _find_rcdata(src, sections, base, RES_ID_OFFSET_TABLE)


def _find_rcdata(src, sections, base, wanted_id):
    """Find RCDATA entry `wanted_id` in the resource tree.

    Resource tree is three levels: type -> name -> language.  SetupLdr stores
    TSetupLdrOffsetTable as RCDATA (type 10) with name 11111.
    """
    d = src.read(base, 4096)

    def entries(off):
        nn, ni = struct.unpack_from('<HH', d, off + 12)
        out = []
        for i in range(nn + ni):
            o = off + 16 + 8 * i
            name, ptr = struct.unpack_from('<II', d, o)
            out.append((name, ptr))
        return out

    def is_dir(ptr):
        return bool(ptr & 0x80000000)

    for rtype, ptr in entries(0):
        if not is_dir(ptr):
            continue
        for rname, ptr2 in entries(ptr & 0x7FFFFFFF):
            if rname != wanted_id or not is_dir(ptr2):
                continue
            for _rlang, ptr3 in entries(ptr2 & 0x7FFFFFFF):
                if is_dir(ptr3):
                    continue
                rva, size, cp, res = struct.unpack_from('<IIII', d, ptr3)
                return {'rva': rva, 'offset': _rva2off(sections, rva),
                        'size': size, 'type': rtype}
    raise InnoFormatError('offset table resource %d not found' % wanted_id)


# --------------------------------------------------------------------------
# Block reader (setup-0.bin)
# --------------------------------------------------------------------------

class BlockReader:
    """Reads a TCompressedBlockWriter block.

    Layout:
        Int32  CRC32 of the 9 header bytes
        Int64  StoredSize   (bytes of payload, including the per-4KiB CRCs)
        Byte   Compressed   (0 = stored, 1 = LZMA1 raw)
        then   StoredSize bytes, each 4096-byte chunk prefixed with its CRC32
    """

    def __init__(self, src, offset):
        self.offset = offset
        hdr_crc, = struct.unpack('<I', src.read(offset, 4))
        hdr = src.read(offset + 4, 9)
        if zlib.crc32(hdr) & 0xFFFFFFFF != hdr_crc:
            raise InnoFormatError('block header CRC mismatch at %#x' % offset)
        self.stored_size, = struct.unpack('<q', hdr[:8])
        self.compressed = bool(hdr[8])
        self.payload_offset = offset + 13

    def read(self, src):
        pos = self.payload_offset
        left = self.stored_size
        raw = bytearray()
        while left > 0:
            crc, = struct.unpack('<I', src.read(pos, 4))
            pos += 4
            left -= 4
            n = min(BLOCK_CHUNK, left)
            data = src.read(pos, n)
            pos += n
            left -= n
            if zlib.crc32(data) & 0xFFFFFFFF != crc:
                raise InnoFormatError('chunk CRC mismatch at %#x' % pos)
            raw += data
        self.end_offset = pos
        if not self.compressed:
            return bytes(raw)
        blob = bytes(raw)
        props = blob[0]
        if props > 9 * 5 * 5 - 1:          # LZMA1 props byte range
            raise InnoFormatError('bad LZMA1 properties byte %d' % props)
        pb, rem = divmod(props, 45)
        lp, lc = divmod(rem, 9)
        dict_size, = struct.unpack('<I', blob[1:5])
        dec = lzma.LZMADecompressor(
            lzma.FORMAT_RAW,
            filters=[{'id': lzma.FILTER_LZMA1, 'lc': lc, 'lp': lp,
                      'pb': pb, 'dict_size': dict_size}])
        return dec.decompress(blob[5:])


# --------------------------------------------------------------------------
# TransformCallInstructions
# --------------------------------------------------------------------------

TRANSFORM_BUF = 0x10000


def transform_call_instructions(buf, encode, addr_offset):
    """Inno Setup rewrites E8/E9 rel32 displacements per 64 KiB buffer.

    Projects/Src/Compression.Base.pas:TransformCallInstructions().  Setup runs
    it with Encode=False after decompression; we must do the same or the PE
    image is corrupted (metadata RVAs drift out of range).
    """
    size = len(buf)
    if size < 5:
        return buf
    limit = size - 4
    i = 0
    while i < limit:
        if buf[i] in (0xE8, 0xE9):
            i += 1
            if buf[i + 3] in (0x00, 0xFF):
                addr = (addr_offset + i + 4) & 0xFFFFFF
                rel = buf[i] | (buf[i + 1] << 8) | (buf[i + 2] << 16)
                if not encode:
                    rel = (rel - addr) & 0xFFFFFFFF
                if rel & 0x800000:
                    buf[i + 3] = (~buf[i + 3]) & 0xFF
                if encode:
                    rel = (rel + addr) & 0xFFFFFFFF
                buf[i] = rel & 0xFF
                buf[i + 1] = (rel >> 8) & 0xFF
                buf[i + 2] = (rel >> 16) & 0xFF
            i += 4
        else:
            i += 1
    return buf


def decode_call_instructions(data):
    """Apply the inverse transform over the whole file."""
    out = bytearray(data)
    addr_offset = 0
    for off in range(0, len(out), TRANSFORM_BUF):
        chunk = out[off:off + TRANSFORM_BUF]
        transform_call_instructions(chunk, False, addr_offset)
        out[off:off + TRANSFORM_BUF] = chunk
        addr_offset = (addr_offset + len(chunk)) & 0xFFFFFFFF
    return bytes(out)


# --------------------------------------------------------------------------
# File-data slice (setup-1.bin)
# --------------------------------------------------------------------------

class SliceReader:
    """Reads one `zlb\\x1a`-prefixed chunk from the embedded data slice."""

    MAGIC = b'zlb\x1a'

    def __init__(self, src, slice_offset):
        self.src = src
        self.slice_offset = slice_offset
        self._cache = (None, None)

    def chunk(self, offset, compressed_size):
        if self._cache[0] == offset:
            return self._cache[1]
        at = self.slice_offset + offset
        if self.src.read(at, 4) != self.MAGIC:
            raise InnoFormatError('bad chunk magic at %#x' % at)
        blob = self.src.read(at + 4, compressed_size)
        props = blob[0]
        if props > 40:
            raise InnoFormatError('bad LZMA2 properties byte %d' % props)
        dict_size = (0xFFFFFFFF if props == 40
                     else (2 | (props & 1)) << (props // 2 + 11))
        dec = lzma.LZMADecompressor(
            lzma.FORMAT_RAW,
            filters=[{'id': lzma.FILTER_LZMA2, 'dict_size': dict_size}])
        data = dec.decompress(blob[1:])
        self._cache = (offset, data)
        return data

    def read(self, location):
        data = self.chunk(location['StartOffset'], location['ChunkCompressedSize'])
        start = location['ChunkSuboffset']
        n = location['OriginalSize']
        out = data[start:start + n]
        if len(out) != n:
            raise InnoFormatError('short read: wanted %d got %d' % (n, len(out)))
        return out
