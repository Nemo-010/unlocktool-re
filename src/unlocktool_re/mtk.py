"""MediaTek xflash command framing, recovered from the IL.

## Frame

`xflash_lib.xsend4` writes a 12-byte header then the payload:

    EF EE EE FE | 01 00 00 00 | 04 00 00 00

The last dword is the payload length. `ForMatSector` does not use `xsend4`;
it writes the same magic with length `0x38` (56) directly, which pins the
command payload size at 56 bytes:

    EF EE EE FE 01 00 00 00 38 00 00 00   (IL_00AF of ForMatSector)

The magic `0xFEEEEEEF` is the documented MTK xflash magic (`Cmd.MAGIC` in
mtkclient's `xflash_param.py`), which is an independent confirmation that this
is the standard MTK DA protocol and not a private one.

## Command payload (56 bytes)

`xflash_lib.cmdformat(partition, start, length)`:

    cmd      = "01 00 00 00"
    selector = "01 00 00 00" if partition == "boot1"
             = "08 00 00 00" if partition == "userarea"
             = ""             otherwise
    s        = penggenapan8(applyshiftKiri2(start))
    l        = penggenapan8(applyshiftKiri2(length))
    zeros    = "00" * 16                      (used twice)
    payload  = HexStringToBytes(cmd + selector + s + l + zeros + zeros)

`cmdread` is byte-for-byte the same function with a different call site.

## The two helpers, literally

`utils.applyshiftKiri2(s)` **reverses the byte order** of the hex string and
then re-pads it to the original width. It is not a shift:

    if len(s) % 2: s = "0" + s
    out = ""
    for i in range(len(s)//2):
        out += s[len(s)-2-2*i : len(s)-2*i]
    out = re.sub("^0+", "", out)
    if len(out) % 2: out = "0" + out
    while len(out)//2 < len(s)//2:
        out = "00" + out
    return out

`utils.penggenapan8(s)` pads on the **right** to 16 hex characters, i.e. to
8 bytes:

    n = len(s)
    pad = {16:"", 14:"00", 12:"0000", 10:"000000", 8:"00000000",
           6:"0000000000", 4:"000000000000", 2:"00000000000000"}.get(n,
           "0000000000000000")
    return s + pad

The name says "8" because the target is 8 *bytes*, not 8 hex digits.

## The byte reversal round-trips

The pair is *not* a bug: `Hex()` produces big-endian hex text, `applyshiftKiri2`
reverses the bytes, and the device reads the field little-endian. The value
survives unchanged:

    Hex(8584*512)              = "431000"
    applyshiftKiri2("431000")  = "001043"
    penggenapan8("001043")     = "0010430000000000"
    read as LE                 = 0x431000 = 4 395 008   (== 8584 * 512)

Verified: `mtk.wire_address(8584) == 8584 * 512`.

## The real bug: a hard-coded 512

`thread_handling.FormatFRP` and `xflash_lib.ReadSector` both call

    Conversions.ToString(ToDouble(start_sector) * 512.0)

with 512 hard-coded, while the operation script declares its own
`SECTOR_SIZE_IN_BYTES`. For the ASUS ROG Phone 2 FRP script the script says
4096 and `start_sector` is 8584, so:

| | bytes |
|---|---|
| the script's real offset (`8584 * 4096`) | 35 160 064 |
| what the tool sends (`8584 * 512`) | 4 395 008 |

That is 8x too small — the erase would land at sector 1073 instead of 8584.
Every script in the shipped tree declares `SECTOR_SIZE_IN_BYTES="4096"` or
`"512"`; the 512 ones are unaffected, the 4096 ones are not.

This is reproduced verbatim, because the point is to model the tool rather
than to fix it. `wire_address()` takes the sector size as an argument so the
discrepancy is testable, and `HARDCODED_SECTOR` names the constant the tool
actually uses.
"""

import re
import struct

MAGIC = 0xFEEEEEEF
FRAME_MAGIC = bytes.fromhex('EFEEEEFE01000000')
CMD_FORMAT = 1
CMD_READ = 1
PAYLOAD_LEN = 56

PARTITION_SELECTOR = {
    'boot1': 1,
    'userarea': 8,
}
DEFAULT_SELECTOR = 0

# The tool hard-codes this regardless of the script's SECTOR_SIZE_IN_BYTES.
HARDCODED_SECTOR = 512

_PAD = {16: '', 14: '00', 12: '0000', 10: '000000', 8: '00000000',
        6: '0000000000', 4: '000000000000', 2: '00000000000000'}


def applyshift_kiri2(s):
    """utils.applyshiftKiri2: reverse byte order, keep width."""
    if len(s) % 2:
        s = '0' + s
    out = ''
    n = len(s)
    for i in range(n // 2):
        out += s[n - 2 - 2 * i:n - 2 * i]
    out = re.sub('^0+', '', out)
    if not out:
        out = ''
    if len(out) % 2:
        out = '0' + out
    while len(out) // 2 < n // 2:
        out = '00' + out
    return out


def penggenapan8(s):
    """utils.penggenapan8: pad on the right to 8 bytes (16 hex chars)."""
    return s + _PAD.get(len(s), '0000000000000000')


def _hex(value):
    """Microsoft.VisualBasic.Conversion.Hex for a non-negative integer."""
    return format(int(value) & 0xFFFFFFFFFFFFFFFF, 'X')


def format_command_value(number):
    """The exact byte string the tool puts on the wire for one address field."""
    return penggenapan8(applyshift_kiri2(_hex(number)))


def wire_address(sector, sector_size=HARDCODED_SECTOR):
    """What the tool sends for a given start sector.

    `sector_size` defaults to the hard-coded 512 the callers use; pass the
    script's real `SECTOR_SIZE_IN_BYTES` to see how far off it lands.
    """
    return int.from_bytes(bytes.fromhex(format_command_value(sector * sector_size)),
                          'little')


def build_command(partition, start, length, command=CMD_FORMAT):
    """Reproduce cmdformat/cmdread exactly.

    `start` and `length` are the values the callers pass, i.e. already
    multiplied by 512.
    """
    selector = PARTITION_SELECTOR.get(str(partition).lower(), DEFAULT_SELECTOR)
    payload = struct.pack('<II', command, selector)
    payload += bytes.fromhex(format_command_value(start))
    payload += bytes.fromhex(format_command_value(length))
    payload += b'\x00' * 32
    assert len(payload) == PAYLOAD_LEN, len(payload)
    return payload


def build_format_command(partition, start, length):
    return build_command(partition, start, length, CMD_FORMAT)


def build_read_command(partition, start, length):
    return build_command(partition, start, length, CMD_READ)


def frame(payload, length=None):
    """The xflash frame: magic, datatype 1, payload length, payload."""
    n = PAYLOAD_LEN if length is None else length
    return FRAME_MAGIC + struct.pack('<I', n) + payload


def parse_frame(data):
    if not data.startswith(FRAME_MAGIC):
        raise ValueError('not an xflash frame')
    if len(data) < 12:
        raise ValueError('short xflash header')
    declared, = struct.unpack_from('<I', data, 8)
    body = data[12:]
    if len(body) < declared:
        raise ValueError('short payload: declared %d got %d' % (declared, len(body)))
    out = {'length': declared, 'payload': body[:declared]}
    if declared >= 8:
        cmd, sel = struct.unpack_from('<II', body, 0)
        out['cmd'] = cmd
        out['partition_selector'] = sel
    if declared >= 24:
        out['start_raw'] = body[8:16].hex()
        out['length_raw'] = body[16:24].hex()
        out['start_value'] = int.from_bytes(body[8:16], 'little')
        out['length_value'] = int.from_bytes(body[16:24], 'little')
    return out


def sector_to_byte(sector, sector_size=512):
    return sector * sector_size
