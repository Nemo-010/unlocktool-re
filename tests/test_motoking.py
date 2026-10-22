"""Tests for the MotoKingProS container and the auth-file inventory."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import motoking  # noqa: E402

PIECES = os.environ.get('UNLOCKTOOL_CHUNKS', '/workspace/src/chunks')


def _installer():
    try:
        from unlocktool_re.installer import Installer
    except ImportError:                       # pragma: no cover
        return None
    parts = sorted(os.path.join(PIECES, p) for p in os.listdir(PIECES)
                   if p.startswith('ut.part')) if os.path.isdir(PIECES) else []
    if not parts:
        return None
    return Installer(parts)


class TestSynthetic(unittest.TestCase):
    def test_roundtrip(self):
        blob = motoking.build('SM-A155F.B5.mt6789_auth_sv5.bin', b'\xaa' * 100)
        b = motoking.parse(blob)
        self.assertEqual(b.version, 4)
        self.assertTrue(b.name.startswith('SM-A155F.B5.mt6789_auth_sv5'))
        self.assertEqual(len(b.payload), 100)
        self.assertEqual(b.tail, b'\x00\x00\x00\x00')

    def test_rejects_other_magic(self):
        self.assertFalse(motoking.is_container(b'MMM\x01' + b'\x00' * 60))
        with self.assertRaises(motoking.MotoKingError):
            motoking.parse(b'MMM\x01' + b'\x00' * 60)

    def test_rejects_truncated(self):
        with self.assertRaises(motoking.MotoKingError):
            motoking.parse(motoking.MAGIC)

    def test_header_integers_are_big_endian(self):
        """A little-endian read gives a nonsense version; BE gives 4."""
        blob = motoking.build('X_auth_sv5.bin', b'')
        self.assertEqual(motoking.parse(blob).version, 4)
        import struct
        self.assertEqual(struct.unpack_from('>I', blob, 0x0C)[0], 4)
        self.assertNotEqual(struct.unpack_from('<I', blob, 0x0C)[0], 4)


@unittest.skipUnless(_installer(), 'installer pieces not available')
class TestRealBlobs(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inst = _installer()
        cls.auth = [f for f in cls.inst.files
                    if f['DestName'].endswith('_auth_sv5.auth')]

    @classmethod
    def tearDownClass(cls):
        cls.inst.close()

    def _blobs(self):
        for f in self.auth:
            data = self.inst.read_file(f)
            if motoking.is_container(data):
                yield f['DestName'], motoking.parse(data)

    def test_there_are_40_blobs(self):
        blobs = list(self._blobs())
        self.assertEqual(len(blobs), 40)
        # two format revisions ship: 'S' (34 files) and 'R' (6 files)
        magics = {}
        for _d, b in blobs:
            magics[b.magic] = magics.get(b.magic, 0) + 1
        self.assertEqual(magics, {b'MotoKingProS': 34, b'MotoKingProR': 6})

    def test_all_are_version_4_and_well_formed(self):
        """`fields` varies per blob (it encodes the payload length class), so
        only the parts that are actually invariant are asserted."""
        seen = set()
        for dest, b in self._blobs():
            self.assertEqual(b.version, 4, dest)
            self.assertEqual(b.fields[0], 0x224D1840, dest)
            self.assertTrue(b.name.startswith('SM-'), dest)
            self.assertGreater(len(b.payload), 1_000_000, dest)
            self.assertEqual(b.tail, b'\x00\x00\x00\x00', dest)
            seen.add(b.fields)
        # exactly three field triples occur, tied to the two magic revisions
        self.assertEqual(len(seen), 3)

    def test_name_encodes_the_chipset(self):
        chips = set()
        for _dest, b in self._blobs():
            for part in b.name.split('.'):
                if part.lower().startswith('mt'):
                    chips.add(part.lower())
        # mt6789 / mt6835 / mt6833 / mt6989 all appear
        self.assertGreaterEqual(len(chips), 4)

    def test_two_da_folders_hold_the_other_models_blob(self):
        """A real merge defect: A156B's DA folder holds A156E's auth blob."""
        swapped = []
        for dest, b in self._blobs():
            parts = dest.replace('\\', '/').split('/')
            folder = parts[-2]
            if not folder.endswith('_DA_BR'):
                continue
            stem = parts[-1].replace('_auth_sv5.auth', '')
            if stem not in folder:
                swapped.append((folder, b.name.split('_auth_sv5')[0]))
        self.assertEqual(len(swapped), 2)
        self.assertIn(('SM-A156B.B5.mt6835_DA_BR', 'SM-A156E.B5.mt6789'), swapped)
        self.assertIn(('SM-A156E.B5.mt6789_DA_BR', 'SM-A156B.B5.mt6835'), swapped)

    def test_every_da_folder_blob_matches_its_folder(self):
        """Apart from the one swap above, folder and blob agree."""
        da = []
        for dest, b in self._blobs():
            parts = dest.replace('\\', '/').split('/')
            folder = parts[-2]
            if not folder.endswith('_DA_BR'):
                continue
            stem = parts[-1].replace('_auth_sv5.auth', '')
            da.append(stem in folder)
        self.assertEqual(len(da), 20)
        self.assertEqual(da.count(False), 2)


@unittest.skipUnless(_installer(), 'installer pieces not available')
class TestAuthInventory(unittest.TestCase):
    """Two unrelated things share the `_auth_sv5.auth` name."""

    @classmethod
    def setUpClass(cls):
        cls.inst = _installer()

    @classmethod
    def tearDownClass(cls):
        cls.inst.close()

    def test_size_classes(self):
        sizes = {}
        for f in self.inst.files:
            if not f['DestName'].endswith('_auth_sv5.auth'):
                continue
            n = len(self.inst.read_file(f))
            sizes[n] = sizes.get(n, 0) + 1
        self.assertEqual(sum(sizes.values()), 42)
        big = sum(v for k, v in sizes.items() if k > 1_000_000)
        small = sum(v for k, v in sizes.items() if k <= 1_000_000)
        self.assertEqual((big, small), (40, 2))

    def test_the_two_small_files_are_mmm_containers(self):
        small = [f for f in self.inst.files
                 if f['DestName'].endswith('_auth_sv5.auth')
                 and len(self.inst.read_file(f)) <= 1_000_000]
        self.assertEqual(len(small), 2)
        for f in small:
            data = self.inst.read_file(f)
            self.assertEqual(data[:4], b'MMM\x01', f['DestName'])

    def test_mmm_block_length_is_u16_and_includes_the_header(self):
        """`MMM\\x01` + u16 len (incl. 8-byte header) + body."""
        import struct
        small = next(f for f in self.inst.files
                     if f['DestName'].endswith('_auth_sv5.auth')
                     and len(self.inst.read_file(f)) <= 1_000_000)
        data = self.inst.read_file(small)
        p = 0
        blocks = []
        while p + 8 <= len(data) and data[p:p + 4] == b'MMM\x01':
            n = struct.unpack_from('<H', data, p + 4)[0]
            if n < 8 or p + n > len(data):
                break
            blocks.append((n, data[p + 8:p + 16]))
            p += n
        self.assertEqual([t[:4] for _n, t in blocks],
                         [b'FILE', b'MTK\x00', b'\x00\x00\x00\x00'])
        # the remainder is a 256-byte signature trailer
        self.assertEqual(len(data) - p, 256)

    def test_the_23_mangled_auth_auth_files_are_7bit_only(self):
        """`auth.auth` is an ASCII-mangled copy: every byte <= 0x7f."""
        count = 0
        for f in self.inst.files:
            if not f['DestName'].endswith('\\auth.auth'):
                continue
            data = self.inst.read_file(f)
            self.assertFalse(any(b > 0x7F for b in data), f['DestName'])
            count += 1
        self.assertEqual(count, 23)


if __name__ == '__main__':
    unittest.main()
