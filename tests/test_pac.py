"""Tests for the Unisoc `.pac` container."""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import pac  # noqa: E402

PIECES = os.environ.get('UNLOCKTOOL_CHUNKS', '/workspace/src/chunks')


def _installer():
    if not os.path.isdir(PIECES):
        return None
    parts = sorted(os.path.join(PIECES, p) for p in os.listdir(PIECES)
                   if p.startswith('ut.part'))
    if not parts:
        return None
    from unlocktool_re.installer import Installer
    return Installer(parts)


def build(version='BP_R1.0.0', product='sp7731e_1h10', firmware='',
          size=None, hi=0, lo=None, count=0, list_start=0):
    total = size or 4096
    buf = bytearray(total)
    buf[0:len(version) * 2] = version.encode('utf-16le')
    struct.pack_into('<I', buf, pac.OFF_HI, hi)
    struct.pack_into('<I', buf, pac.OFF_LO,
                     total if lo is None else lo)
    buf[pac.OFF_PRODUCT:pac.OFF_PRODUCT + len(product) * 2] = \
        product.encode('utf-16le')
    buf[pac.OFF_FIRMWARE:pac.OFF_FIRMWARE + len(firmware) * 2] = \
        firmware.encode('utf-16le')
    struct.pack_into('<I', buf, pac.OFF_COUNT, count)
    struct.pack_into('<I', buf, pac.OFF_LIST, list_start)
    return bytes(buf)


class TestHeader(unittest.TestCase):
    def test_offsets(self):
        self.assertEqual(pac.OFF_VERSION, 0)
        self.assertEqual(pac.OFF_HI, 44)
        self.assertEqual(pac.OFF_LO, 48)
        self.assertEqual(pac.OFF_PRODUCT, 52)
        self.assertEqual(pac.OFF_FIRMWARE, 180)
        self.assertEqual(pac.OFF_COUNT, 308)
        self.assertEqual(pac.OFF_LIST, 312)

    def test_roundtrip(self):
        h = pac.parse(build())
        self.assertEqual(h.sz_version, 'BP_R1.0.0')
        self.assertEqual(h.product_name, 'sp7731e_1h10')
        self.assertEqual(h.firmware_name, '')
        self.assertTrue(h.supported)

    def test_header_size_is_hi_shifted(self):
        # header_size is hi<<32 | lo; the size check only fires when it
        # exceeds the file, so a huge hi is expected to be rejected.
        h = pac.parse(build(hi=0, lo=0x800, size=0x2000))
        self.assertEqual(h.header_size, 0x800)
        with self.assertRaises(pac.PacError):
            pac.parse(build(hi=1, lo=0x1000, size=0x2000))

    def test_second_supported_version(self):
        h = pac.parse(build(version='BP_R2.0.1'))
        self.assertTrue(h.supported)

    def test_unsupported_version_rejected(self):
        with self.assertRaises(pac.PacError) as ctx:
            pac.parse(build(version='BP_R3.0.0'))
        self.assertIn('Unsupported PAC version', str(ctx.exception))

    def test_oversized_header_rejected(self):
        with self.assertRaises(pac.PacError) as ctx:
            pac.parse(build(size=1024, lo=999999))
        self.assertIn("size is not correct", str(ctx.exception))

    def test_short_file_rejected(self):
        with self.assertRaises(pac.PacError):
            pac.parse(b'\x00' * 100)

    def test_is_pac(self):
        self.assertTrue(pac.is_pac(build()))
        self.assertFalse(pac.is_pac(b'\x7fELF' + b'\x00' * 400))
        self.assertFalse(pac.is_pac(b''))


@unittest.skipUnless(_installer(), 'installer pieces not available')
class TestRealPacs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inst = _installer()
        cls.pacs = [f for f in cls.inst.files
                    if f['DestName'].lower().endswith('.pac')]

    @classmethod
    def tearDownClass(cls):
        cls.inst.close()

    def test_29_pac_files(self):
        self.assertEqual(len(self.pacs), 29)

    def test_exactly_one_is_in_the_format_the_tool_implements(self):
        ok = []
        for f in self.pacs:
            data = self.inst.read_file(f)
            try:
                h = pac.parse(data)
            except pac.PacError:
                continue
            ok.append((f['DestName'], h))
        self.assertEqual(len(ok), 1)
        dest, h = ok[0]
        self.assertIn('NOKIA', dest)
        self.assertEqual(h.sz_version, 'BP_R1.0.0')
        self.assertEqual(h.product_name, 'sp7731e_1h10')
        # dwLoSize is the whole file
        self.assertEqual(h.header_size, 941376)

    def test_the_28_realme_files_share_one_prefix(self):
        """A constant 48-byte block: they are a different, opaque variant."""
        prefixes = {}
        for f in self.pacs:
            data = self.inst.read_file(f)
            if 'REALME' not in f['DestName']:
                continue
            prefixes[data[:48]] = prefixes.get(data[:48], 0) + 1
        self.assertEqual(len(prefixes), 1)
        self.assertEqual(sum(prefixes.values()), 28)
        self.assertEqual(
            list(prefixes)[0][:8].hex(), '6cdd713d5f57dcd4')

    def test_realme_files_fail_the_version_gate(self):
        for f in self.pacs:
            if 'REALME' not in f['DestName']:
                continue
            with self.assertRaises(pac.PacError) as ctx:
                pac.parse(self.inst.read_file(f))
            self.assertIn('Unsupported PAC version', str(ctx.exception))
            return


if __name__ == '__main__':
    unittest.main()
