"""Tests for the MediaTek scatter parser (ColokTool.RDA.MtkScatter)."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import scatter  # noqa: E402

TREE = os.environ.get('UNLOCKTOOL_TREE',
                      '/workspace/unlocktool-re/artifacts/tree/data')

SAMPLE = '''\
#####################################################################
#  General Setting
#####################################################################
- general: MTK_PLATFORM_CFG
  info:
    - config_version: V1.1.2
      platform: MT6737M
      project: D281L
      storage: EMMC
      block_size: 0x20000
#####################################################################
#  Layout Setting
#####################################################################
- partition_index: SYS0
  partition_name: preloader
  file_name: preloader.bin
  is_download: true
  type: SV5_BL_BIN
  linear_start_addr: 0x0
  physical_start_addr: 0x0
  partition_size: 0x40000
  region: EMMC_BOOT_1
  storage: HW_STORAGE_EMMC
  operation_type: BOOTLOADERS

- partition_index: SYS21
  partition_name: frp
  file_name: NONE
  is_download: false
  type: NORMAL_ROM
  linear_start_addr: 0x13c00000
  physical_start_addr: 0x13c00000
  partition_size: 0x100000
  region: EMMC_USER
  storage: HW_STORAGE_EMMC
  operation_type: INVISIBLE
'''

# the deeper-indented variant some vendors ship
SAMPLE_INDENTED = SAMPLE.replace('\n- partition_index:', '\n  - partition_index:') \
                        .replace('\n  partition_', '\n    partition_') \
                        .replace('\n  file_', '\n    file_') \
                        .replace('\n  is_', '\n    is_') \
                        .replace('\n  type:', '\n    type:') \
                        .replace('\n  linear_', '\n    linear_') \
                        .replace('\n  physical_', '\n    physical_') \
                        .replace('\n  region:', '\n    region:') \
                        .replace('\n  storage:', '\n    storage:') \
                        .replace('\n  operation_', '\n    operation_')


class TestSynthetic(unittest.TestCase):
    def test_general_block(self):
        s = scatter.parse(SAMPLE)
        self.assertEqual(s.general['platform'], 'MT6737M')
        self.assertEqual(s.general['project'], 'D281L')
        self.assertEqual(s.general['storage'], 'EMMC')
        self.assertEqual(s.general['block_size'], '0x20000')

    def test_entries(self):
        s = scatter.parse(SAMPLE)
        self.assertEqual(len(s.entries), 2)
        self.assertEqual([e.index for e in s.entries], ['SYS0', 'SYS21'])
        self.assertEqual([e.name for e in s.entries], ['preloader', 'frp'])

    def test_downloads_only_counts_real_payloads(self):
        s = scatter.parse(SAMPLE)
        self.assertEqual([e.name for e in s.downloads()], ['preloader'])
        # frp says file_name: NONE, so it is described but not written
        frp = s.by_name('frp')
        self.assertFalse(frp.has_payload)
        self.assertFalse(frp.is_download)

    def test_addresses_are_ints(self):
        s = scatter.parse(SAMPLE)
        self.assertEqual(s.by_name('preloader').linear_start_addr, 0)
        self.assertEqual(s.by_name('frp').linear_start_addr, 0x13C00000)
        self.assertEqual(s.by_name('frp').partition_size, 0x100000)

    def test_indented_variant_parses_identically(self):
        a = scatter.parse(SAMPLE)
        b = scatter.parse(SAMPLE_INDENTED)
        self.assertEqual([e.name for e in a.entries],
                         [e.name for e in b.entries])
        self.assertEqual(b.general.get('platform'), 'MT6737M')

    def test_empty_and_garbage(self):
        self.assertEqual(scatter.parse('').error, 'empty scatter file')
        self.assertEqual(scatter.parse('hello').error,
                         'no partition_index entries')

    def test_is_scatter_text(self):
        self.assertTrue(scatter.is_scatter_text(SAMPLE))
        self.assertFalse(scatter.is_scatter_text('<root/>'))
        self.assertFalse(scatter.is_scatter_text(None))


@unittest.skipUnless(os.path.isdir(TREE), 'data tree not available')
class TestRealScatterFiles(unittest.TestCase):
    def test_every_android_txt_parses(self):
        from unlocktool_re.datatree import DataTree
        tree = DataTree(TREE)
        ok = 0
        bad = []
        for brand in tree.all_brands():
            for model in brand.models:
                path = os.path.join(tree.model_dir(brand.brand, model.key),
                                    'android.txt')
                if not os.path.isfile(path):
                    continue
                s = scatter.load(path)
                if s and not s.error and s.entries:
                    ok += 1
                else:
                    bad.append((brand.brand, model.key,
                                s.error if s else 'unreadable'))
        self.assertEqual(ok, 158)
        self.assertEqual(bad, [])

    def test_platform_is_recorded_for_every_file(self):
        from unlocktool_re.datatree import DataTree
        tree = DataTree(TREE)
        missing = []
        for brand in tree.all_brands():
            for model in brand.models:
                path = os.path.join(tree.model_dir(brand.brand, model.key),
                                    'android.txt')
                if not os.path.isfile(path):
                    continue
                s = scatter.load(path)
                if not s.general.get('platform'):
                    missing.append(model.key)
        self.assertEqual(missing, [])

    def test_every_scatter_declares_an_frp_partition(self):
        """FRP reset is the tool's headline operation, so the partition it
        needs must be described in the scatter file."""
        from unlocktool_re.datatree import DataTree
        tree = DataTree(TREE)
        missing = []
        for brand in tree.all_brands():
            for model in brand.models:
                path = os.path.join(tree.model_dir(brand.brand, model.key),
                                    'android.txt')
                if not os.path.isfile(path):
                    continue
                s = scatter.load(path)
                if not s.by_name('frp'):
                    missing.append((brand.brand, model.key))
        # measured: all 158 scatter files describe an frp partition
        self.assertEqual(missing, [])


if __name__ == '__main__':
    unittest.main()
