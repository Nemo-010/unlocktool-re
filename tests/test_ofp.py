"""Tests for the OPPO `.ofp` container reader.

No `.ofp` file ships in the archive, so these tests are built on synthetic
fixtures generated to the same rules the IL encodes.  That makes the reader
*simulated*, not verified — see docs/validation-report.md.
"""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import ofp  # noqa: E402

XML = (b'<?xml version="1.0" encoding="utf-8"?>\n'
       b'<root><part name="frp" size="0x100000"/></root>\n')


class TestHelpers(unittest.TestCase):
    """The three tiny functions the format is built from."""

    def test_unpack_reverses_byte_pairs(self):
        # Unpack splits into 2-char groups and concatenates back to front.
        self.assertEqual(ofp.unpack('01020304'), '04030201')
        # it reverses the *groups*, not the bytes within them
        self.assertEqual(ofp.unpack('aabbccddeeff'), 'ffeeddccbbaa')
        self.assertEqual(ofp.unpack(''), '')
        self.assertEqual(ofp.unpack('aabb'), 'bbaa')

    def test_unpack_is_an_involution(self):
        for s in ('01020304', 'aabbccddeeff', '00112233'):
            self.assertEqual(ofp.unpack(ofp.unpack(s)), s)

    def test_hex_to_dec_is_val_amp_h(self):
        self.assertEqual(ofp.hex_to_dec('00000001'), 1)
        self.assertEqual(ofp.hex_to_dec('ff'), 255)
        with self.assertRaises(ofp.OfpError):
            ofp.hex_to_dec('zz')

    def test_read_uint_le_is_little_endian(self):
        """bytes 01 00 00 00 -> '01000000' -> Unpack -> '00000001' -> 1."""
        data = bytes.fromhex('01000000')
        self.assertEqual(ofp.read_uint_le(data, 0), 1)
        self.assertEqual(ofp.read_uint_le(bytes.fromhex('00010000'), 0), 256)

    def test_ceil16(self):
        self.assertEqual(ofp.ceil16(0), 0)
        self.assertEqual(ofp.ceil16(1), 16)
        self.assertEqual(ofp.ceil16(16), 16)
        self.assertEqual(ofp.ceil16(17), 32)
        self.assertEqual(ofp.ceil16(100), 112)

    def test_short_read(self):
        with self.assertRaises(ofp.OfpError):
            ofp.read_uint_le(b'\x01\x02', 0)


class TestParse(unittest.TestCase):
    def test_page_512(self):
        f = ofp.parse(ofp.build(XML, page_size=512, size=512 * 8))
        self.assertEqual(f.page_size, 512)
        self.assertEqual(f.xml[:len(XML)], XML)

    def test_page_4096(self):
        f = ofp.parse(ofp.build(XML, page_size=4096, size=4096 * 8))
        self.assertEqual(f.page_size, 4096)
        self.assertEqual(f.xml[:len(XML)], XML)

    def test_xml_size_is_recorded(self):
        f = ofp.parse(ofp.build(XML, page_size=512, size=512 * 8))
        self.assertEqual(f.xml_size, len(XML))
        # the region is rounded up to a 16-byte multiple
        self.assertEqual(len(f.xml), ofp.ceil16(len(XML)))

    def test_probe_marker_is_required(self):
        blob = bytearray(ofp.build(XML, page_size=512, size=4096))
        probe = len(blob) + 16 - 512
        blob[probe:probe + 4] = b'\x00\x00\x00\x00'
        with self.assertRaises(ofp.OfpError) as ctx:
            ofp.parse(bytes(blob))
        self.assertIn('page-size probe', str(ctx.exception))

    def test_bad_xml_offset_rejected(self):
        blob = bytearray(ofp.build(XML, page_size=512, size=4096))
        base = len(blob) - 512
        struct.pack_into('<I', blob, base + 20, 0xFFFFFF)
        with self.assertRaises(ofp.OfpError) as ctx:
            ofp.parse(bytes(blob))
        self.assertIn('outside the file', str(ctx.exception))

    def test_probe_order_prefers_512(self):
        """GetXml tries 512 first; a file matching both must report 512."""
        blob = ofp.build(XML, page_size=512, size=512 * 8)
        self.assertEqual(ofp.detect_page_size(blob), 512)

    def test_empty_input(self):
        with self.assertRaises(ofp.OfpError):
            ofp.parse(b'')


class TestAgainstRealOfpIfPresent(unittest.TestCase):
    """Runs only if someone points OFP_SAMPLE at a real .ofp."""

    @unittest.skipUnless(os.environ.get('OFP_SAMPLE'),
                         'set OFP_SAMPLE to a real .ofp')
    def test_real_file(self):
        f = ofp.parse_file(os.environ['OFP_SAMPLE'])
        self.assertIn(f.page_size, (512, 4096))
        self.assertIn(b'<', f.xml)


if __name__ == '__main__':
    unittest.main()
