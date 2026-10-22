"""Integration tests against the real 2.3 GB installer."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))
sys.path.insert(0, HERE)

from conftest_paths import installer_pieces, installer_path  # noqa: E402
from unlocktool_re import inno, crypto  # noqa: E402
from unlocktool_re.installer import Installer  # noqa: E402


def _pieces():
    p = installer_path()
    return [p] if p else installer_pieces()


PIECES = _pieces()


def skip_if_missing(obj):
    return unittest.skipUnless(PIECES, 'installer not available '
                                         '(set UNLOCKTOOL_CHUNKS or '
                                         'UNLOCKTOOL_INSTALLER)')(obj)


@skip_if_missing
class TestContainer(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.inst = Installer(PIECES)

    @classmethod
    def tearDownClass(cls):
        cls.inst.close()

    def test_setup_version(self):
        self.assertEqual(self.inst.version, 'Inno Setup Setup Data (6.7.0)')

    def test_loader_table(self):
        t = self.inst.table
        self.assertEqual(t['version'], 2)
        self.assertEqual(t['total_size'], 2327092946)
        self.assertEqual(t['offset0'], 0x8A9C1D1E)
        self.assertEqual(t['offset1'], 0x105200)

    def test_headers_fully_consumed(self):
        s = self.inst.setup0
        self.assertEqual(s['block1_trailing'], 0)
        self.assertEqual(s['block2_trailing'], 0)

    def test_no_setup_encryption(self):
        self.assertEqual(self.inst.encryption['use'], 0)
        self.assertEqual(self.inst.encryption['kdf_iterations'], 220000)

    def test_entry_counts(self):
        h = self.inst.header
        s = self.inst.setup0
        for name, key in (('files', 'NumFileEntries'),
                          ('locations', 'NumFileLocationEntries'),
                          ('dirs', 'NumDirEntries'),
                          ('languages', 'NumLanguageEntries'),
                          ('tasks', 'NumTaskEntries'),
                          ('icons', 'NumIconEntries'),
                          ('run', 'NumRunEntries')):
            self.assertEqual(len(s[name]), h[key], name)

    def test_app_identity(self):
        h = self.inst.header
        self.assertEqual(h['AppName'], 'UNLOCKTOOL ALBASHAA')
        self.assertEqual(h['AppPublisher'], 'ALAASHAA PRO TEAM')
        self.assertEqual(h['AppVersion'], '2026.09.23.0')
        self.assertEqual(h['DefaultDirName'], '{autopf}\\UNLOCKTOOL ALBASHAA')
        self.assertEqual(h['ArchitecturesAllowed'], 'x64compatible')

    def test_dest_names_unique(self):
        names = self.inst.dest_names()
        self.assertEqual(len(names), len(set(names)))
        self.assertEqual(len(names), 7386)

    def test_payload_size_matches_index(self):
        total = sum(loc['OriginalSize'] for loc in self.inst.locations)
        self.assertEqual(total, 4322930069)

    def test_read_embedded_exe(self):
        exe = self.inst.read_path('ColokTool.exe')
        self.assertEqual(exe[:2], b'MZ')
        self.assertEqual(len(exe), 51785728)

    def test_read_small_file(self):
        self.assertEqual(self.inst.read_path('data\\verson.txt'),
                         b'2026.09.23.0\n')
        self.assertIn(b'owner', self.inst.read_path('data\\accounts\\accounts.json'))


@skip_if_missing
class TestPayloadCrypto(unittest.TestCase):
    """programs.bin must decrypt to ELF with the recovered scheme."""

    @classmethod
    def setUpClass(cls):
        cls.inst = Installer(PIECES)
        cls.by_name = {}
        for f in cls.inst.files:
            if f['DestName'].endswith('programs.bin'):
                cls.by_name[f['DestName']] = f

    @classmethod
    def tearDownClass(cls):
        cls.inst.close()

    def _load(self, needle):
        for name, entry in self.by_name.items():
            if needle in name:
                return self.inst.read_file(entry)
        self.skipTest('payload %r not in image' % needle)

    def test_asus_rog_phone_2_is_elf(self):
        data = self._load('Asus ROG Phone 2 [ZS660KL]')
        plain = crypto.decrypt_programs_bin(data)
        self.assertTrue(crypto.is_elf(plain), plain[:16].hex())
        self.assertEqual(plain[:4], b'\x7fELF')

    def test_second_password_does_not_work(self):
        data = self._load('Asus ROG Phone 2 [ZS660KL]')
        plain = crypto.decrypt_programs_bin(data, crypto.PASSWORD_RDA_SEC)
        self.assertFalse(crypto.is_elf(plain))

    def test_majority_of_payloads_decrypt(self):
        ok = 0
        total = 0
        for name, entry in self.by_name.items():
            total += 1
            data = self.inst.read_file(entry)
            try:
                plain = crypto.decrypt_programs_bin(data)
            except ValueError:
                continue
            if crypto.is_elf(plain):
                ok += 1
        # measured: 543 of 606; the rest are a mix of a different key and
        # non-ELF payloads.  Guard the ratio so a regression is visible.
        self.assertEqual(total, 606)
        self.assertGreaterEqual(ok, 540)


if __name__ == '__main__':
    unittest.main()
