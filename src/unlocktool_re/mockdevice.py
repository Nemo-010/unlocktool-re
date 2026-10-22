"""A mock MediaTek xflash device, and the client state machine that drives it.

The command framing is recovered from `xflash_lib.cmdformat/cmdread` and
`Port.send00000/writemtk/readmtk` (see mtk.py).  What we could not recover from
static analysis is the *device-side* reply format: the tool reads back an
arbitrary number of bytes and only checks that the first 8 hex characters
equal its `magichex` field, which is set at runtime by the DA handshake and is
not a compile-time constant.

So the mock below is a documented assumption, not a reproduction of observed
hardware.  It exists to exercise the client state machine and its error
handling; `MockDevice.assumption` records that explicitly, and the validation
report lists this as simulated-only.
"""

import os
import struct

from . import mtk

# Reply magic used by the mock.  The real value comes from the DA handshake.
MOCK_MAGIC = bytes.fromhex('5A5AA5A5')


class DeviceError(Exception):
    pass


class MockDevice:
    """Minimal xflash target: accepts frames, records them, replies.

    Configuration knobs let tests drive each failure path the client has:
      * `fail_after`      stop replying after N commands (timeout)
      * `bad_magic`       reply with the wrong magic (protocol error)
      * `reject`          reply with an explicit error status
    """

    assumption = ('Reply format is a documented mock: 4-byte magic + status '
                  'dword + echoed length. The real DA reply magic is only '
                  'known after the handshake, so this is simulated-only.')

    def __init__(self, magic=MOCK_MAGIC, fail_after=None, bad_magic=False,
                 reject=False):
        self.magic = magic
        self.fail_after = fail_after
        self.bad_magic = bad_magic
        self.reject = reject
        self.received = []
        self.inbox = bytearray()
        self.partitions = {}
        self._erased = []
        self._written = []
        self._patched = []
        self.fail_on_call = None        # raise on the Nth mutation (1-based)
        self._calls = 0

    # -- transport ---------------------------------------------------------
    def write(self, data):
        self.inbox += data
        self.pump()

    def read(self, n):
        out = bytes(self.inbox[:n])
        del self.inbox[:n]
        return out

    # -- framing -----------------------------------------------------------
    def pump(self):
        """Process every complete frame sitting in the inbox."""
        while len(self.inbox) >= len(mtk.FRAME_MAGIC) + 48:
            if not self.inbox.startswith(mtk.FRAME_MAGIC):
                raise DeviceError('bad frame magic')
            frame = bytes(self.inbox[:len(mtk.FRAME_MAGIC) + 48])
            del self.inbox[:len(frame)]
            self.received.append(mtk.parse_frame(frame))
            if self.fail_after is not None and \
                    len(self.received) > self.fail_after:
                return                      # simulate a silent device
            self._reply(frame)

    def _reply(self, frame):
        if self.reject:
            status = 1
        else:
            status = 0
            cmd = mtk.parse_frame(frame)
            if cmd['cmd'] == 1:
                self._erased.append((cmd['partition_selector'],
                                     cmd['start_byte'], cmd['length_bytes']))
        magic = b'\x00\x00\x00\x00' if self.bad_magic else self.magic
        self.inbox += magic + struct.pack('<II', status, len(frame))

    # -- operation-level API (driven by plan.execute_plan) -----------------
    def _maybe_fail(self):
        self._calls += 1
        if self.fail_on_call is not None and self._calls >= self.fail_on_call:
            raise DeviceError('simulated failure on call %d' % self._calls)

    def erase(self, start_byte, length_bytes, label=None, ppn=None):
        self._maybe_fail()
        self._erased.append({'start': start_byte, 'length': length_bytes,
                             'label': label, 'ppn': ppn})

    def write_range(self, start_byte, path, label=None, ppn=None):
        self._maybe_fail()
        size = os.path.getsize(path) if os.path.isfile(path) else 0
        self._written.append({'start': start_byte, 'size': size,
                              'label': label, 'ppn': ppn, 'path': path})

    def patch(self, absolute_byte, value, size_bytes, ppn=None):
        self._maybe_fail()
        self._patched.append({'at': absolute_byte, 'value': value,
                              'size': size_bytes, 'ppn': ppn})

    # -- observations ------------------------------------------------------
    @property
    def erased_ranges(self):
        return list(self._erased)

    @property
    def written_ranges(self):
        return list(self._written)

    @property
    def patches(self):
        return list(self._patched)


class XflashClient:
    """The subset of the tool's command path we can drive without hardware."""

    def __init__(self, transport, magic=MOCK_MAGIC):
        self.transport = transport
        self.magic = magic

    def send(self, payload):
        frame = mtk.frame(payload)
        self.transport.write(frame)

    def read_reply(self, size=8):
        data = self.transport.read(size)
        if len(data) < size:
            raise DeviceError('short reply: wanted %d got %d'
                              % (size, len(data)))
        return data

    def command(self, payload):
        self.send(payload)
        reply = self.read_reply(4 + 4 + 4)
        if reply[:4] != self.magic:
            raise DeviceError('bad reply magic %s' % reply[:4].hex())
        status, echoed = struct.unpack('<II', reply[4:])
        if status != 0:
            raise DeviceError('device reported status %d' % status)
        return {'status': status, 'echoed_length': echoed}

    def format_range(self, partition, start_byte, length_bytes):
        return self.command(
            mtk.build_format_command(partition, start_byte, length_bytes))

    def read_range(self, partition, start_byte, length_bytes):
        return self.command(
            mtk.build_read_command(partition, start_byte, length_bytes))
