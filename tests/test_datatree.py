"""Tests for the offline data tree, operation scripts and MTK framing."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))
sys.path.insert(0, HERE)

from conftest_paths import installer_pieces  # noqa: E402
from unlocktool_re import crypto, firehose, mtk  # noqa: E402
from unlocktool_re.datatree import (BrandIndex, DataTree, ModelEntry,  # noqa: E402
                                    OperationSet, audit_model,
                                    referenced_payloads)

TREE = os.environ.get('UNLOCKTOOL_TREE', '/workspace/unlocktool-re/artifacts/tree/data')


def have_tree():
    return os.path.isdir(TREE)


BRAND_XML = '''<?xml version="1.0" encoding="UTF-8"?>
<data>
  <program Devices="Acme Phone 1 [A1]" />
  <program Devices="Acme Phone 2 [A2]" />
  <name Devices="Acme Phone 1" Models="[A1]" Platform="Snapdragon 855" EDL="edl" Patch="" />
  <name Devices="Acme Phone 2" Models="[A2]" Platform="MT6765" Broom="brom" Patch="" />
  <name Devices="Acme Phone 3" Models="[A3]" Platform="Exynos" Conn="" Patch="" />
  <method Devices="Acme Phone 1 [A1]" M1="[EDL] RESET FRP" M2="[EDL] FACTORY RESET" M3="" M4="" M5="" M6="" M7="" M8="" />
  <method Devices="Acme Phone 2 [A2]" M1="[BROM] RESET FRP" M2="" M3="" M4="" M5="" M6="" M7="" M8="" />
</data>
'''

FRP_SCRIPT = '''<?xml version="1.0" ?>
<data>
  <program SECTOR_SIZE_IN_BYTES="4096" filename="" label="frp" num_partition_sectors="128" physical_partition_number="0" size_in_KB="512.0" sparse="false" start_sector="8584" />
</data>
'''

FACTORY_SCRIPT = '''<?xml version="1.0" ?>
<data>
  <program SECTOR_SIZE_IN_BYTES="4096" filename="misc" label="misc" num_partition_sectors="256" physical_partition_number="0" size_in_KB="1024.0" sparse="false" start_sector="8200" />
  <program SECTOR_SIZE_IN_BYTES="4096" filename="" label="frp" num_partition_sectors="128" physical_partition_number="0" size_in_KB="512.0" sparse="false" start_sector="8584" />
</data>
'''


class TestBrandIndex(unittest.TestCase):
    def setUp(self):
        self.idx = BrandIndex('ACME', BRAND_XML)

    def test_sections(self):
        self.assertEqual(self.idx.programs,
                         ['Acme Phone 1 [A1]', 'Acme Phone 2 [A2]'])
        self.assertEqual(len(self.idx.models), 3)
        self.assertEqual(len(self.idx.operations), 2)

    def test_model_key_is_devices_plus_models(self):
        self.assertEqual(self.idx.models[0].key, 'Acme Phone 1 [A1]')
        self.assertEqual(self.idx.models[2].key, 'Acme Phone 3 [A3]')

    def test_lookup(self):
        m = self.idx.model('Acme Phone 1', '[A1]')
        self.assertIsNotNone(m)
        self.assertEqual(m.platform, 'Snapdragon 855')
        self.assertEqual(m.edl, 'edl')
        self.assertIsNone(self.idx.model('Acme Phone 1', '[NOPE]'))

    def test_operation_slots(self):
        ops = self.idx.operations_for('Acme Phone 1 [A1]')
        self.assertEqual(ops.operations, ['[EDL] RESET FRP', '[EDL] FACTORY RESET'])
        # empty slots are dropped, not kept as empty strings
        self.assertEqual(len(self.idx.operations_for('Acme Phone 2 [A2]').operations), 1)

    def test_payload_advertisement(self):
        self.assertTrue(self.idx.has_payload('Acme Phone 1 [A1]'))
        self.assertFalse(self.idx.has_payload('Acme Phone 3 [A3]'))

    def test_operation_set_handles_m10(self):
        ops = OperationSet({'Devices': 'X', 'M1': 'a', 'M10': 'j'})
        self.assertEqual(ops.operations, ['a', 'j'])

    def test_model_entry_attrs_kept(self):
        m = ModelEntry({'Devices': 'D', 'Models': 'M', 'Soc': 's'})
        self.assertEqual(m.attrs['Soc'], 's')
        self.assertEqual(m.key, 'D M')


class TestDataTreeSynthetic(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        data = os.path.join(self.root, 'data')
        os.makedirs(os.path.join(data, 'ACME', 'Acme Phone 1 [A1]'))
        os.makedirs(os.path.join(data, 'ACME', 'Acme Phone 2 [A2]'))
        os.makedirs(os.path.join(data, 'accounts'))
        with open(os.path.join(data, 'ACME', 'acme.xml'), 'w') as fh:
            fh.write(BRAND_XML)
        with open(os.path.join(data, 'ACME', 'Acme Phone 1 [A1]',
                               '[EDL] RESET FRP'), 'w') as fh:
            fh.write(FRP_SCRIPT)
        with open(os.path.join(data, 'ACME', 'Acme Phone 1 [A1]',
                               '[EDL] FACTORY RESET'), 'w') as fh:
            fh.write(FACTORY_SCRIPT)
        # Phone 2 advertises an operation but has no script -> "broken button"
        with open(os.path.join(data, 'accounts', 'accounts.json'), 'w') as fh:
            fh.write('[{"UserName": "owner", "Email": "o@x", "Password": "owner"}]')
        self.data = data
        self.tree = DataTree(data)

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_brand_discovery(self):
        self.assertEqual(self.tree.brand_names(), ['ACME'])

    def test_audit_complete_model(self):
        m = self.tree.brand('ACME').model('Acme Phone 1', '[A1]')
        r = audit_model(self.tree, 'ACME', m)
        self.assertTrue(r['payload_folder'])
        self.assertFalse(r['programs_bin'])
        self.assertEqual(r['missing_scripts'], [])
        self.assertEqual(r['operations'],
                         ['[EDL] RESET FRP', '[EDL] FACTORY RESET'])

    def test_audit_detects_missing_script(self):
        m = self.tree.brand('ACME').model('Acme Phone 2', '[A2]')
        r = audit_model(self.tree, 'ACME', m)
        self.assertEqual(r['missing_scripts'], ['[BROM] RESET FRP'])

    def test_operation_script_read(self):
        text = self.tree.read_operation_script('ACME', 'Acme Phone 1 [A1]',
                                               '[EDL] RESET FRP')
        self.assertIn('label="frp"', text)
        self.assertIsNone(self.tree.read_operation_script(
            'ACME', 'Acme Phone 1 [A1]', 'nope'))

    def test_accounts(self):
        accts = self.tree.load_accounts()
        self.assertEqual(len(accts), 1)
        self.assertIsNotNone(self.tree.find_account(accts, 'OWNER'))
        self.assertIsNotNone(self.tree.find_account(accts, 'o@x'))
        self.assertIsNone(self.tree.find_account(accts, 'nobody'))

    def test_missing_accounts_file_is_empty(self):
        os.unlink(self.tree.accounts_path())
        self.assertEqual(self.tree.load_accounts(), [])


class TestRawProgram(unittest.TestCase):
    def test_erase_only(self):
        rp = firehose.RawProgram('frp', FRP_SCRIPT)
        self.assertIsNone(rp.error)
        self.assertEqual(len(rp.entries), 1)
        self.assertEqual(rp.entries[0].action, 'erase')
        self.assertEqual(rp.entries[0].label, 'frp')
        self.assertEqual(rp.entries[0].start_sector, 8584)
        self.assertEqual(rp.entries[0].start_byte, 8584 * 4096)

    def test_write_and_erase(self):
        rp = firehose.RawProgram('factory', FACTORY_SCRIPT)
        self.assertEqual(len(rp.writes), 1)
        self.assertEqual(len(rp.label_erases), 1)   # filename="" -> erase by label
        self.assertEqual(len(rp.erases), 0)         # no <erase> element here
        self.assertEqual(rp.payload_names(), ['misc'])

    def test_bad_xml_is_reported_not_raised(self):
        rp = firehose.RawProgram('bad', '<data><program')
        self.assertIsNotNone(rp.error)
        self.assertEqual(rp.entries, [])

    def test_missing_file(self):
        self.assertIsNone(firehose.load_rawprogram('/nonexistent', 'x'))


class TestReferencedPayloads(unittest.TestCase):
    def test_finds_filenames(self):
        refs = referenced_payloads(FACTORY_SCRIPT)
        self.assertIn('misc', refs)
        self.assertIn('frp', refs)

    def test_empty(self):
        self.assertEqual(referenced_payloads(''), [])
        self.assertEqual(referenced_payloads(None), [])


class TestMtkFraming(unittest.TestCase):
    def test_default_selector(self):
        cmd = mtk.build_format_command('frp', 8584 * 512, 128 * 512)
        parsed = mtk.parse_frame(mtk.frame(cmd))
        self.assertEqual(parsed['cmd'], 1)
        self.assertEqual(parsed['partition_selector'], 0)
        self.assertEqual(parsed['start_value'], 8584 * 512)
        self.assertEqual(parsed['length_value'], 128 * 512)

    def test_boot1_selector(self):
        cmd = mtk.build_read_command('boot1', 1, 2)
        parsed = mtk.parse_frame(mtk.frame(cmd))
        self.assertEqual(parsed['partition_selector'], 1)

    def test_userarea_selector(self):
        cmd = mtk.build_format_command('userarea', 0, 0)
        parsed = mtk.parse_frame(mtk.frame(cmd))
        self.assertEqual(parsed['partition_selector'], 8)

    def test_case_insensitive_partition(self):
        a = mtk.build_format_command('BOOT1', 5, 5)
        b = mtk.build_format_command('boot1', 5, 5)
        self.assertEqual(a, b)

    def test_reserved_is_32_zero_bytes(self):
        cmd = mtk.build_format_command('x', 0, 0)
        self.assertEqual(cmd[24:], b'\x00' * 32)
        self.assertEqual(len(cmd), 56)

    def test_reject_bad_frame(self):
        with self.assertRaises(ValueError):
            mtk.parse_frame(b'\x00' * 56)


@unittest.skipUnless(have_tree(), 'extracted data tree not available')
class TestRealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.tree = DataTree(TREE)

    def test_brand_list(self):
        brands = self.tree.brand_names()
        for expected in ('ASUS', 'XIAOMI', 'SAMSUNG', 'OPPO', 'VIVO',
                         'REALME', 'HUAWEI', 'MEIZU'):
            self.assertIn(expected, brands)

    def test_asus_index_parses(self):
        b = self.tree.brand('ASUS')
        self.assertGreater(len(b.models), 20)
        self.assertGreater(len(b.operations), 20)
        m = b.models[0]
        self.assertTrue(b.has_payload(m.key))

    def test_asus_frp_script_is_erase_only(self):
        rp = firehose.load_rawprogram(
            self.tree.model_dir('ASUS', 'Asus ROG Phone 2 [ZS660KL]'),
            '[EDL] RESET FRP')
        self.assertIsNotNone(rp)
        self.assertEqual([e.label for e in rp.entries], ['frp'])
        self.assertEqual(rp.entries[0].action, 'erase')

    def test_asus_factory_script_writes_misc(self):
        rp = firehose.load_rawprogram(
            self.tree.model_dir('ASUS', 'Asus ROG Phone 2 [ZS660KL]'),
            '[EDL] FACTORY RESET')
        self.assertEqual(rp.payload_names(), ['misc'])

    def _scan_scripts(self):
        out = []
        for brand in self.tree.all_brands():
            for op in brand.operations:
                for name in op.operations:
                    rp = firehose.load_rawprogram(
                        self.tree.model_dir(brand.brand, op.devices), name)
                    out.append((brand.brand, op.devices, name, rp))
        return out

    def test_script_inventory_is_stable(self):
        """Counts measured over the shipped tree; a change means new data."""
        rows = self._scan_scripts()
        present = [r for r in rows if r[3] is not None]
        missing = [r for r in rows if r[3] is None]
        broken = [r for r in present if r[3].error]
        self.assertEqual(len(rows), 2230)
        self.assertEqual(len(present), 989)
        self.assertEqual(len(missing), 1241)
        self.assertEqual(len(broken), 21)

    def test_broken_scripts_are_the_known_three_kinds(self):
        """21 scripts are broken: 8 empty, 8 with trailing 'EndCF', 5 truncated."""
        rows = self._scan_scripts()
        kinds = {}
        for brand, key, name, rp in rows:
            if rp is None or not rp.error:
                continue
            if rp.error == 'empty script':
                kind = 'empty'
            elif 'junk after document element' in rp.error:
                kind = 'trailing-text'
            elif 'no element found' in rp.error:
                kind = 'truncated'
            else:
                kind = rp.error
            kinds[kind] = kinds.get(kind, 0) + 1
        self.assertEqual(kinds, {'empty': 8, 'trailing-text': 8,
                                 'truncated': 5})

    def test_known_good_scripts_have_expected_entries(self):
        rows = self._scan_scripts()
        good = [r for r in rows if r[3] is not None and not r[3].error]
        self.assertEqual(len(good), 968)
        with_patch = [r for r in good if r[3].patches]
        with_erase = [r for r in good if r[3].erases]
        self.assertEqual(len(with_patch), 392)
        self.assertEqual(len(with_erase), 90)

    def test_salvage_recovers_elements_from_broken_scripts(self):
        rp = firehose.load_rawprogram(
            self.tree.model_dir('ASUS', 'Asus ROG Phone 2 [ZS660KL]'),
            '[EDL] RESET EFS')
        self.assertIsNotNone(rp.error)
        # the three <program> rows are still readable
        self.assertEqual([e.label for e in rp.programs],
                         ['fsg', 'modemst1', 'modemst2'])


if __name__ == '__main__':
    unittest.main()
