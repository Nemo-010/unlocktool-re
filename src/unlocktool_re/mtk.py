"""MediaTek BROM/xflash command framing, recovered from the IL.

`xflash_lib.cmdformat(partition, start, length)` and `cmdread(...)` build the
same 24-byte command payload; only the first dword differs (0x01 = format,
0x01 too, the selector is the per-partition dword).  The IL is:

    "01 00 00 00"                         // cmd
    selector = "01 00 00 00"  if partition == "boot1"
             = "08 00 00 00"  if partition == "userarea"
             = ""             otherwise
    start    = penggenapan8(applyshiftKiri2(start))
    length   = penggenapan8(applyshiftKiri2(length))
    "00"*16                               // reserved
    "00"*16                               // reserved

`applyshiftKiri2` is `Val(x) << 2` rendered back as 8 hex digits: the values
the callers pass are sector counts, and shifting by 2 turns them into byte
addresses (x4).  `penggenapan8` zero-pads the hex string to 8 characters,
i.e. it is a 32-bit little-endian field.

So the payload is:

    uint32 cmd            (1)
    uint32 partition_sel  (1 = boot1, 8 = userarea, 0 = default)
    uint32 start_byte
    uint32 length_bytes
    uint8[32] reserved

`xsend4` wraps it in the xflash frame magic `EF EE EE FE 01 00 00 00 04 00 00 00`
before the payload, which is the documented DA "command" packet form.
"""

import struct

FRAME_MAGIC = bytes.fromhex('EFEEEEFE0100000004000000')
CMD_FORMAT = 1
CMD_READ = 1

PARTITION_SELECTOR = {
    'boot1': 1,
    'userarea': 8,
}
DEFAULT_SELECTOR = 0


def _shift_left_2(value):
    """utils.applyshiftKiri2: interpret the text as a number, multiply by 4."""
    return (int(value) << 2) & 0xFFFFFFFF


def build_command(partition, start, length, command=CMD_FORMAT):
    selector = PARTITION_SELECTOR.get(partition.lower(), DEFAULT_SELECTOR)
    return struct.pack('<IIII', command, selector,
                       _shift_left_2(start), _shift_left_2(length)) + b'\x00' * 32


def build_format_command(partition, start, length):
    return build_command(partition, start, length, CMD_FORMAT)


def build_read_command(partition, start, length):
    return build_command(partition, start, length, CMD_READ)


def frame(payload):
    """xflash_lib.xsend4: magic + payload."""
    return FRAME_MAGIC + payload


def parse_frame(data):
    if not data.startswith(FRAME_MAGIC):
        raise ValueError('not an xflash command frame')
    body = data[len(FRAME_MAGIC):]
    if len(body) < 16:
        raise ValueError('short command payload')
    cmd, sel, start, length = struct.unpack_from('<IIII', body, 0)
    return {'cmd': cmd, 'partition_selector': sel, 'start_byte': start,
            'length_bytes': length, 'reserved': body[16:]}


def sector_to_byte(sector, sector_size=512):
    return sector * sector_size
