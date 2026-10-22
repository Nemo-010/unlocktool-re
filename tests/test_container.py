"""Tests for the non-ELF loader container."""
import os
import struct
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import container, crypto  # noqa: E402

TREE = os.environ.get('UNLOCKTOOL_TREE',
                      '/workspace/unlocktool-re/artifacts/tree/data')


class TestSynthetic(unittest.TestCase):
    def test_roundtrip(self):
        payload = bytes(range(256)) * 4
        blob = container.build(0xF800C000, payload)
        c = container.parse(blob)
        self.assertEqual(c.payload, payload)
        self.assertEqual(c.load_addr, 0xF800C000)
        self.assertEqual(c.payload_len, len(payload))
        self.assertEqual(c.header_len, 0x50)
        self.assertEqual(c.sector_size, 0x100)

    def test_rejects_other_data(self):
        self.assertFalse(container.is_container(b'\x7fELF' + b'\x00' * 100))
        with self.assertRaises(container.ContainerError):
            container.parse(b'\x7fELF' + b'\x00' * 100)

    def test_rejects_truncated(self):
        with self.assertRaises(container.ContainerError):
            container.parse(struct.pack('<2I', container.MAGIC,
                                        container.MAGIC2))

    def test_rejects_length_mismatch(self):
        blob = bytearray(container.build(0xF800C000, b'x' * 64))
        struct.pack_into('<I', blob, 0x1C, 128)     # lie about payload_len
        with self.assertRaises(container.ContainerError) as ctx:
            container.parse(bytes(blob))
        self.assertIn('does not match', str(ctx.exception))

    def test_rejects_bad_header_len(self):
        blob = bytearray(container.build(0xF800C000, b'x' * 64))
        struct.pack_into('<I', blob, 0x14, 0x40)
        with self.assertRaises(container.ContainerError):
            container.parse(bytes(blob))


@unittest.skipUnless(os.path.isdir(TREE), 'data tree not available')
class TestRealPayloads(unittest.TestCase):
    def _family(self):
        from unlocktool_re.datatree import DataTree
        tree = DataTree(TREE)
        out = []
        for brand in tree.all_brands():
            for model in brand.models:
                path = tree.programs_path(brand.brand, model.key)
                if not os.path.isfile(path):
                    continue
                with open(path, 'rb') as fh:
                    raw = fh.read()
                plain = crypto.decrypt_programs_bin(raw)
                if container.is_container(plain):
                    out.append((brand.brand, model.key, plain))
        return out

    def test_all_six_parse(self):
        fam = self._family()
        self.assertEqual(len(fam), 6)
        for brand, key, plain in fam:
            c = container.parse(plain)
            self.assertEqual(c.magic, container.MAGIC, key)
            self.assertEqual(c.header_len, 0x50, key)
            self.assertEqual(c.payload_len, len(plain) - 0x50, key)
            self.assertIn(c.count, (13, 21), key)
            self.assertGreaterEqual(c.load_addr, 0xF8000000, key)
            self.assertLessEqual(c.load_addr, 0xF80FFFFF, key)

    @staticmethod
    def _is_arm32(words):
        """ARM32: B <off> is cond=0b1110, bits 27..25 = 0b101."""
        return words[0] >> 28 == 0xE and (words[0] >> 25) & 7 == 5

    @staticmethod
    def _is_arm64(words):
        """ARM64: BL is 100101, RET is 1101011001011111000000..."""
        return (words[0] >> 26) in (0b100101,) or words[-1] == 0xD65F03C0

    def test_payload_is_arm_code(self):
        """Both an ARM32 and an ARM64 pre-loader occur in the family."""
        arm32 = arm64 = 0
        for brand, key, plain in self._family():
            c = container.parse(plain)
            words = struct.unpack_from('<16I', c.payload, 0)
            if self._is_arm32(words):
                arm32 += 1
            elif self._is_arm64(words):
                arm64 += 1
            else:
                self.fail('%s: not ARM code: %r'
                          % (key, ['%08x' % w for w in words[:4]]))
        self.assertEqual((arm32, arm64), (5, 1))


if __name__ == '__main__':
    unittest.main()
