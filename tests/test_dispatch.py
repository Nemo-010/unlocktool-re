"""Tests for operation dispatch classification."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import dispatch  # noqa: E402

TREE = os.environ.get('UNLOCKTOOL_TREE',
                      '/workspace/unlocktool-re/artifacts/tree/data')


class TestFamily(unittest.TestCase):
    def test_edl(self):
        self.assertEqual(dispatch.family_of('[EDL] RESET FRP'),
                         dispatch.FAMILY_EDL)

    def test_brom(self):
        self.assertEqual(dispatch.family_of('[BROM] RESET FRP'),
                         dispatch.FAMILY_BROM)

    def test_meta(self):
        self.assertEqual(dispatch.family_of('[META] FORMAT DATA'),
                         dispatch.FAMILY_META)

    def test_sideload(self):
        self.assertEqual(dispatch.family_of('[SIDELOAD] FORMAT DATA'),
                         dispatch.FAMILY_SIDELOAD)

    def test_prefix_is_case_insensitive(self):
        self.assertEqual(dispatch.family_of('[edl] reset frp'),
                         dispatch.FAMILY_EDL)

    def test_legacy_unprefixed_is_edl(self):
        # older brand indexes predate the prefix convention
        self.assertEqual(dispatch.family_of('Reset FRP'), dispatch.FAMILY_EDL)
        self.assertEqual(dispatch.family_of('Format Data'), dispatch.FAMILY_EDL)

    def test_arbitrary_unprefixed_is_unknown(self):
        self.assertEqual(dispatch.family_of('Do Something'), dispatch.FAMILY_UNKNOWN)

    def test_payload_names_are_not_operations(self):
        for name in ('misc', 'misc_emmc', 'misc_ufs', 'kernel', 'config',
                     '1', '2', '3', '4', '90', '91', 'persist_0'):
            self.assertEqual(dispatch.family_of(name),
                             dispatch.FAMILY_UNKNOWN, name)

    def test_empty(self):
        self.assertEqual(dispatch.family_of(''), dispatch.FAMILY_UNKNOWN)
        self.assertEqual(dispatch.family_of(None), dispatch.FAMILY_UNKNOWN)


class TestAction(unittest.TestCase):
    def test_frp(self):
        self.assertEqual(dispatch.action_of('[EDL] RESET FRP'), 'frp-erase')
        self.assertEqual(dispatch.action_of('Reset FRP'), 'frp-erase')

    def test_factory_reset_variants(self):
        self.assertEqual(dispatch.action_of('[EDL] FACTORY RESET'),
                         'factory-reset')
        self.assertEqual(dispatch.action_of('[EDL] FACTORY RESET 2'),
                         'factory-reset')
        self.assertEqual(dispatch.action_of('[EDL] FACTORY RESET + FRP'),
                         'factory-reset+frp')

    def test_cloud_lock(self):
        self.assertEqual(dispatch.action_of('[EDL] UNLOCK MI CLOUD - TAM'),
                         'cloud-lock-remove')
        self.assertEqual(dispatch.action_of('[EDL] PATCH DISABLE MICLOUD'),
                         'cloud-lock-disable')

    def test_bootloader(self):
        self.assertEqual(dispatch.action_of('[EDL] UNLOCK BOOTLOADER'),
                         'bootloader-unlock')
        self.assertEqual(dispatch.action_of('[EDL] RELOCK BOOTLOADER'),
                         'bootloader-relock')

    def test_vendor_typo_still_classified(self):
        self.assertEqual(dispatch.action_of('[EDL] UNLOCK BOOTOADER'),
                         'bootloader-unlock')

    def test_efs(self):
        self.assertEqual(dispatch.action_of('[EDL] [Oxygen] RESET EFS'),
                         'efs-reset')

    def test_unknown(self):
        self.assertEqual(dispatch.action_of('[EDL] SOMETHING ELSE'), 'other')

    def test_imei(self):
        self.assertEqual(
            dispatch.action_of('[EDL] INSTANN IMEI TO 0 [MODEM BD V3]'),
            'imei-write')


class TestSimulatedFlag(unittest.TestCase):
    def test_edl_is_not_simulated(self):
        self.assertNotIn(dispatch.FAMILY_EDL, dispatch.SIMULATED_ONLY)

    def test_brom_and_meta_are_simulated(self):
        self.assertIn(dispatch.FAMILY_BROM, dispatch.SIMULATED_ONLY)
        self.assertIn(dispatch.FAMILY_META, dispatch.SIMULATED_ONLY)


@unittest.skipUnless(os.path.isdir(TREE), 'data tree not available')
class TestResolveAgainstRealTree(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        from unlocktool_re.datatree import DataTree
        cls.tree = DataTree(TREE)

    def test_resolves_a_complete_model(self):
        d = dispatch.resolve(self.tree, 'ASUS',
                             'Asus ROG Phone 2 [ZS660KL]', '[EDL] RESET FRP')
        self.assertEqual(d.family, dispatch.FAMILY_EDL)
        self.assertEqual(d.action, 'frp-erase')
        self.assertEqual(d.reason, '')
        self.assertFalse(d.simulated)

    def test_reports_missing_payload_folder(self):
        d = dispatch.resolve(self.tree, 'XIAOMI', 'Xiaomi 11T [Agate]',
                             '[EDL] RESET FRP')
        self.assertIn('payload folder missing', d.reason)
        self.assertIn('operation script missing', d.reason)

    def test_reports_unknown_model(self):
        d = dispatch.resolve(self.tree, 'ASUS', 'Nonexistent Phone [ZZ]',
                             '[EDL] RESET FRP')
        self.assertIn('model not in brand index', d.reason)

    def test_every_distinct_operation_classifies(self):
        seen = set()
        for brand in self.tree.all_brands():
            for op in brand.operations:
                for name in op.operations:
                    seen.add(name)
        self.assertEqual(len(seen), 55)
        unknown = {n for n in seen if dispatch.family_of(n) ==
                   dispatch.FAMILY_UNKNOWN}
        # 12 of the 55 are payload filenames, not operations
        self.assertEqual(unknown, dispatch.KNOWN_BAD)


if __name__ == '__main__':
    unittest.main()
