"""The second loader container found in the data tree.

Six of the 528 `programs.bin` files decrypt to something that is not ELF.  All
six share a self-describing header, recovered by inspection and confirmed
against the file length:

    off 0x00  u32   magic        0x844BDCD1
    off 0x04  u32   magic2       0x73D71034
    off 0x08  u32   count        13 or 21 in the shipped files
    off 0x0c  u32   reserved     0xFFFFFFFF
    off 0x10  u32   reserved     0xFFFFFFFF
    off 0x14  u32   header_len   0x50
    off 0x18  u32   load_addr    0xF800C000 / 0xF800C050
    off 0x1c  u32   payload_len
    off 0x20  u32   load_addr2   0x00049000 / 0x000141D4
    off 0x24  u32   load_end2    0xF8055000 / 0xF8020224
    off 0x28  u32   sector_size  0x100
    off 0x2c  u32   sector_base  0xF8055100 / 0xF8020324
    off 0x30  u32   chunk_size   0x1800
    off 0x34  u32   flag         1
    off 0x38  u32   flag         1
    off 0x3c..0x50  reserved     0xFFFFFFFF

The invariant that makes this a real parse rather than a guess:

    payload_len == file_size - header_len

holds exactly for every file in this family.  The payload starts with ARM
branch trampolines (`06 00 00 EA`, `05 00 00 EA`, ...), i.e. it is a small
pre-loader / download-agent stub rather than a firehose ELF — which is why the
tool's `Contains("ELF")` check rejects it.
"""

import struct

MAGIC = 0x844BDCD1
MAGIC2 = 0x73D71034
HEADER_LEN = 0x50


class ContainerError(Exception):
    pass


class LoaderContainer:
    __slots__ = ('magic', 'magic2', 'count', 'header_len', 'load_addr',
                 'payload_len', 'load_addr2', 'load_end2', 'sector_size',
                 'sector_base', 'chunk_size', 'flags', 'payload')

    def __init__(self, **kw):
        for name in self.__slots__:
            setattr(self, name, kw.get(name))

    def as_dict(self):
        return {n: getattr(self, n) for n in self.__slots__ if n != 'payload'}

    def __repr__(self):
        return ('LoaderContainer(count=%d load=%#x len=%#x sector=%#x)'
                % (self.count, self.load_addr or 0, self.payload_len or 0,
                   self.sector_size or 0))


def is_container(data):
    return len(data) >= HEADER_LEN and \
        struct.unpack_from('<I', data, 0)[0] == MAGIC and \
        struct.unpack_from('<I', data, 4)[0] == MAGIC2


def parse(data):
    if not is_container(data):
        raise ContainerError('not a 0x%08X container' % MAGIC)
    (magic, magic2, count, r0, r1, header_len, load_addr,
     payload_len) = struct.unpack_from('<8I', data, 0)
    (load_addr2, load_end2, sector_size, sector_base,
     chunk_size) = struct.unpack_from('<5I', data, 0x20)
    flags = struct.unpack_from('<2I', data, 0x34)
    if header_len != HEADER_LEN:
        raise ContainerError('unexpected header_len %#x' % header_len)
    body = data[header_len:]
    if payload_len != len(body):
        raise ContainerError(
            'payload_len %#x does not match file body %#x'
            % (payload_len, len(body)))
    return LoaderContainer(
        magic=magic, magic2=magic2, count=count, header_len=header_len,
        load_addr=load_addr, payload_len=payload_len, load_addr2=load_addr2,
        load_end2=load_end2, sector_size=sector_size, sector_base=sector_base,
        chunk_size=chunk_size, flags=flags, payload=body)


def build(load_addr, payload, count=13, load_addr2=0x00049000,
          load_end2=0xF8055000, sector_size=0x100, sector_base=0xF8055100,
          chunk_size=0x1800, flags=(1, 1)):
    """Emit a container that `parse` accepts — used by the round-trip test."""
    hdr = struct.pack('<8I', MAGIC, MAGIC2, count, 0xFFFFFFFF, 0xFFFFFFFF,
                      HEADER_LEN, load_addr, len(payload))
    hdr += struct.pack('<5I', load_addr2, load_end2, sector_size, sector_base,
                       chunk_size)
    hdr += struct.pack('<2I', *flags)
    hdr += b'\xff' * (HEADER_LEN - len(hdr))
    assert len(hdr) == HEADER_LEN
    return hdr + payload
