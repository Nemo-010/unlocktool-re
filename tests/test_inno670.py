"""Unit tests for the Inno Setup container primitives.

The integration tests against the real installer live in
test_real_installer.py; this file only exercises the building blocks.
"""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import inno, setup0  # noqa: E402

class TestCallInstructionTransform(unittest.TestCase):
    """The transform must be its own inverse."""

    def test_roundtrip_preserves_bytes(self):
        import random
        rng = random.Random(1234)
        # build a buffer with plenty of E8/E9 near-relative calls
        buf = bytearray(rng.randrange(256) for _ in range(4096))
        for i in range(0, 4000, 37):
            buf[i] = 0xE8
            buf[i + 1] = rng.randrange(256)
            buf[i + 2] = rng.randrange(256)
            buf[i + 3] = 0xFF
        original = bytes(buf)
        inno.transform_call_instructions(buf, True, 0)
        self.assertNotEqual(bytes(buf), original)
        inno.transform_call_instructions(buf, False, 0)
        self.assertEqual(bytes(buf), original)

    def test_skips_non_call_opcodes(self):
        buf = bytearray(b'\x90\x90\x90\x90\x90')
        before = bytes(buf)
        inno.transform_call_instructions(buf, True, 0)
        self.assertEqual(bytes(buf), before)

    def test_high_byte_must_be_00_or_ff(self):
        buf = bytearray(b'\xE8\x11\x22\x33\x44')
        before = bytes(buf)
        inno.transform_call_instructions(buf, True, 0)
        self.assertEqual(bytes(buf), before)


class TestBlockReader(unittest.TestCase):
    def _make_block(self, payload, compressed=False):
        """Emit a stored block: header CRC + Int64 size + Bool + CRC'd chunks."""
        import struct
        import zlib
        body = bytearray()
        for i in range(0, len(payload), 4096):
            chunk = payload[i:i + 4096]
            body += struct.pack('<I', zlib.crc32(chunk) & 0xFFFFFFFF)
            body += chunk
        hdr = struct.pack('<q', len(body)) + bytes([1 if compressed else 0])
        return struct.pack('<I', zlib.crc32(hdr) & 0xFFFFFFFF) + hdr + bytes(body)

    def test_stored_block(self):
        import tempfile
        payload = b'abcdef' * 1000
        blob = self._make_block(payload)
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            src = inno.ChunkSource.from_paths([path])
            reader = inno.BlockReader(src, 0)
            self.assertEqual(reader.read(src), payload)
            self.assertFalse(reader.compressed)
            src.close()
        finally:
            os.unlink(path)

    def test_corrupt_chunk_crc_detected(self):
        import tempfile
        payload = b'x' * 8192
        blob = bytearray(self._make_block(payload))
        blob[-1] ^= 0xFF
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            src = inno.ChunkSource.from_paths([path])
            reader = inno.BlockReader(src, 0)
            with self.assertRaises(inno.InnoFormatError):
                reader.read(src)
            src.close()
        finally:
            os.unlink(path)

    def test_corrupt_header_crc_detected(self):
        import tempfile
        blob = bytearray(self._make_block(b'hello'))
        blob[0] ^= 0xFF
        with tempfile.NamedTemporaryFile(delete=False) as fh:
            fh.write(blob)
            path = fh.name
        try:
            src = inno.ChunkSource.from_paths([path])
            with self.assertRaises(inno.InnoFormatError):
                inno.BlockReader(src, 0)
            src.close()
        finally:
            os.unlink(path)


class TestChunkSource(unittest.TestCase):
    def test_reads_across_pieces(self):
        import tempfile
        with tempfile.NamedTemporaryFile(delete=False) as a, \
                tempfile.NamedTemporaryFile(delete=False) as b:
            a.write(b'0123456789')
            b.write(b'abcdefghij')
            pa, pb = a.name, b.name
        try:
            src = inno.ChunkSource.from_paths([pa, pb])
            self.assertEqual(src.size, 20)
            self.assertEqual(src.read(5, 10), b'56789abcde')
            self.assertEqual(src.read(0, 20), b'0123456789abcdefghij')
            self.assertEqual(src.read(18, 2), b'ij')
            self.assertEqual(src.read(20, 5), b'')
            src.close()
        finally:
            os.unlink(pa)
            os.unlink(pb)


if __name__ == '__main__':
    unittest.main()
