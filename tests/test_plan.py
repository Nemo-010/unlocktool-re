"""Tests for plan building and mock execution."""
import os
import shutil
import sys
import tempfile
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import mockdevice, plan  # noqa: E402

TREE = os.environ.get('UNLOCKTOOL_TREE',
                      '/workspace/unlocktool-re/artifacts/tree/data')


class FakeTree:
    """Minimal stand-in for DataTree, so the plan logic can be tested alone."""

    def __init__(self, root):
        self.root = root

    def has_payload_dir(self, brand, key):
        return os.path.isdir(self.model_dir(brand, key))

    def model_dir(self, brand, key):
        return os.path.join(self.root, brand, key)


FRP = '''<?xml version="1.0" ?>
<data>
  <program SECTOR_SIZE_IN_BYTES="4096" filename="" label="frp"
           num_partition_sectors="128" physical_partition_number="0"
           size_in_KB="512.0" sparse="false" start_sector="8584" />
</data>
'''

FACTORY = '''<?xml version="1.0" ?>
<data>
  <program SECTOR_SIZE_IN_BYTES="4096" filename="misc" label="misc"
           num_partition_sectors="256" physical_partition_number="0"
           size_in_KB="1024.0" sparse="false" start_sector="8200" />
  <program SECTOR_SIZE_IN_BYTES="4096" filename="" label="frp"
           num_partition_sectors="128" physical_partition_number="0"
           size_in_KB="512.0" sparse="false" start_sector="8584" />
</data>
'''

MIXED = '''<?xml version="1.0" ?>
<data>
  <erase SECTOR_SIZE_IN_BYTES="512" num_partition_sectors="1024"
         physical_partition_number="0" start_sector="11484184" />
  <patches>
    <patch SECTOR_SIZE_IN_BYTES="512" byte_offset="8" filename="DISK"
           physical_partition_number="0" size_in_bytes="8"
           start_sector="11926528" value="0" what="Zero."/>
  </patches>
</data>
'''


class PlanTestCase(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.dir = os.path.join(self.root, 'ACME', 'Phone 1 [A1]')
        os.makedirs(self.dir)
        self.tree = FakeTree(self.root)

    def tearDown(self):
        shutil.rmtree(self.root)

    def write(self, name, text):
        with open(os.path.join(self.dir, name), 'w') as fh:
            fh.write(text)

    def test_erase_only_plan(self):
        self.write('frp', FRP)
        steps = plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'frp')
        self.assertEqual(len(steps), 1)
        s = steps[0]
        self.assertEqual(s.kind, 'erase')
        self.assertEqual(s.label, 'frp')
        self.assertEqual(s.start_byte, 8584 * 4096)
        self.assertEqual(s.length_bytes, 128 * 4096)

    def test_write_then_erase_order(self):
        self.write('factory', FACTORY)
        open(os.path.join(self.dir, 'misc'), 'wb').write(b'\x00' * 64)
        steps = plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'factory')
        self.assertEqual([s.kind for s in steps], ['write', 'erase'])
        self.assertEqual(steps[0].payload, os.path.join(self.dir, 'misc'))

    def test_mixed_erase_and_patch(self):
        self.write('mixed', MIXED)
        steps = plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'mixed')
        self.assertEqual([s.kind for s in steps], ['erase', 'patch'])
        self.assertEqual(steps[0].start_byte, 11484184 * 512)
        self.assertEqual(steps[1].start_byte, 11926528 * 512)
        self.assertEqual(steps[1].byte_offset, 8)

    def test_missing_folder(self):
        with self.assertRaises(plan.PlanError) as ctx:
            plan.build_plan(self.tree, 'ACME', 'No Such Phone [Z]', 'frp')
        self.assertIn('payload folder missing', str(ctx.exception))

    def test_missing_script(self):
        with self.assertRaises(plan.PlanError) as ctx:
            plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'nope')
        self.assertIn('operation script missing', str(ctx.exception))

    def test_broken_script(self):
        self.write('broken', '<data><program')
        with self.assertRaises(plan.PlanError) as ctx:
            plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'broken')
        self.assertIn('not usable', str(ctx.exception))

    def test_missing_payload_file(self):
        self.write('factory', FACTORY)          # references "misc", not created
        with self.assertRaises(plan.PlanError) as ctx:
            plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'factory')
        self.assertIn('payload missing: misc', str(ctx.exception))

    def test_empty_script_is_rejected(self):
        self.write('empty', '   \n')
        with self.assertRaises(plan.PlanError) as ctx:
            plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]', 'empty')
        self.assertIn('not usable', str(ctx.exception))


class TestExecution(unittest.TestCase):
    def setUp(self):
        self.root = tempfile.mkdtemp()
        self.dir = os.path.join(self.root, 'ACME', 'Phone 1 [A1]')
        os.makedirs(self.dir)
        self.tree = FakeTree(self.root)
        open(os.path.join(self.dir, 'misc'), 'wb').write(b'\x00' * 64)
        open(os.path.join(self.dir, 'factory'), 'w').write(FACTORY)
        self.steps = plan.build_plan(self.tree, 'ACME', 'Phone 1 [A1]',
                                     'factory')

    def tearDown(self):
        shutil.rmtree(self.root)

    def test_success(self):
        dev = mockdevice.MockDevice()
        r = plan.execute_plan(self.steps, dev)
        self.assertTrue(r.ok)
        self.assertEqual(len(r.completed), 2)
        self.assertEqual(len(dev.written_ranges), 1)
        self.assertEqual(len(dev.erased_ranges), 1)
        self.assertEqual(dev.written_ranges[0]['size'], 64)

    def test_device_failure_aborts(self):
        dev = mockdevice.MockDevice()
        dev.fail_on_call = 1
        r = plan.execute_plan(self.steps, dev)
        self.assertFalse(r.ok)
        self.assertIn('simulated failure', r.error)
        # the factory plan is [write misc, erase frp]; the first step fails
        self.assertEqual(r.failed.kind, 'write')
        self.assertEqual(len(r.completed), 0)

    def test_cancellation(self):
        dev = mockdevice.MockDevice()
        r = plan.execute_plan(self.steps, dev, stop_after=1)
        self.assertFalse(r.ok)
        self.assertEqual(r.error, 'cancelled by caller')
        self.assertEqual(len(r.completed), 1)

    def test_partial_completion_is_reported(self):
        dev = mockdevice.MockDevice()
        dev.fail_on_call = 2
        r = plan.execute_plan(self.steps, dev)
        self.assertFalse(r.ok)
        self.assertEqual(len(r.completed), 1)
        self.assertEqual(r.failed.kind, 'erase')


@unittest.skipUnless(os.path.isdir(TREE), 'data tree not available')
class TestPlanCoverage(unittest.TestCase):
    """The headline measurement: how many advertised operations are runnable."""

    @classmethod
    def setUpClass(cls):
        from unlocktool_re.datatree import DataTree
        cls.tree = DataTree(TREE)

    def test_runnable_operation_count(self):
        ok = 0
        total = 0
        steps = 0
        reasons = {}
        for brand in self.tree.all_brands():
            for op in brand.operations:
                for name in op.operations:
                    total += 1
                    try:
                        s = plan.build_plan(self.tree, brand.brand,
                                            op.devices, name)
                    except plan.PlanError as exc:
                        key = str(exc).split(':')[0]
                        reasons[key] = reasons.get(key, 0) + 1
                        continue
                    ok += 1
                    steps += len(s)
        self.assertEqual(total, 2230)
        self.assertEqual(ok, 841)
        self.assertEqual(steps, 46447)
        self.assertEqual(reasons, {
            'payload folder missing': 1116,
            'payload missing': 126,
            'operation script missing': 125,
            'operation script is not usable (XML parse error': 13,
            'operation script is not usable (empty script)': 8,
            'operation script produced no steps': 1,
        })

    def test_a_real_frp_plan_executes_on_the_mock(self):
        steps = plan.build_plan(self.tree, 'ASUS',
                                'Asus ROG Phone 2 [ZS660KL]',
                                '[EDL] RESET FRP')
        dev = mockdevice.MockDevice()
        r = plan.execute_plan(steps, dev)
        self.assertTrue(r.ok)
        self.assertEqual(dev.erased_ranges[0]['label'], 'frp')
        self.assertEqual(dev.erased_ranges[0]['start'], 8584 * 4096)

    def test_every_runnable_plan_executes_on_the_mock(self):
        ran = 0
        for brand in self.tree.all_brands():
            for op in brand.operations:
                for name in op.operations:
                    try:
                        steps = plan.build_plan(self.tree, brand.brand,
                                                op.devices, name)
                    except plan.PlanError:
                        continue
                    dev = mockdevice.MockDevice()
                    r = plan.execute_plan(steps, dev)
                    self.assertTrue(r.ok, '%s/%s: %s' % (op.devices, name,
                                                         r.error))
                    ran += 1
        self.assertEqual(ran, 841)


if __name__ == '__main__':
    unittest.main()
