"""Client/mock-device protocol tests."""
import os
import sys
import unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.join(HERE, '..', 'src'))

from unlocktool_re import mockdevice, mtk  # noqa: E402


class TestHappyPath(unittest.TestCase):
    def setUp(self):
        self.dev = mockdevice.MockDevice()
        self.cli = mockdevice.XflashClient(self.dev)

    def test_format_roundtrip(self):
        reply = self.cli.format_range('frp', 8584 * 512, 128 * 512)
        self.assertEqual(reply['status'], 0)
        self.assertEqual(len(self.dev.received), 1)
        cmd = self.dev.received[0]
        self.assertEqual(cmd['partition_selector'], 0)
        self.assertEqual(cmd['start_value'], 8584 * 512)

    def test_boot1_selector_reaches_device(self):
        self.cli.format_range('boot1', 1, 2)
        self.assertEqual(self.dev.received[0]['partition_selector'], 1)

    def test_userarea_selector_reaches_device(self):
        self.cli.format_range('userarea', 1, 2)
        self.assertEqual(self.dev.received[0]['partition_selector'], 8)

    def test_sequence_of_commands(self):
        for i in range(5):
            self.cli.format_range('frp', i * 512, 512)
        self.assertEqual(len(self.dev.received), 5)
        self.assertEqual([c['start_value'] for c in self.dev.received],
                         [i * 512 for i in range(5)])


class TestFailureModes(unittest.TestCase):
    def test_silent_device_times_out(self):
        dev = mockdevice.MockDevice(fail_after=0)
        cli = mockdevice.XflashClient(dev)
        with self.assertRaises(mockdevice.DeviceError):
            cli.format_range('frp', 0, 512)

    def test_bad_magic_rejected(self):
        dev = mockdevice.MockDevice(bad_magic=True)
        cli = mockdevice.XflashClient(dev)
        with self.assertRaises(mockdevice.DeviceError) as ctx:
            cli.format_range('frp', 0, 512)
        self.assertIn('bad reply magic', str(ctx.exception))

    def test_device_error_status_rejected(self):
        dev = mockdevice.MockDevice(reject=True)
        cli = mockdevice.XflashClient(dev)
        with self.assertRaises(mockdevice.DeviceError) as ctx:
            cli.format_range('frp', 0, 512)
        self.assertIn('status 1', str(ctx.exception))

    def test_short_reply_rejected(self):
        class ShortTransport:
            def write(self, data):
                pass

            def read(self, n):
                return b'\x00' * (n - 1)

        cli = mockdevice.XflashClient(ShortTransport())
        with self.assertRaises(mockdevice.DeviceError) as ctx:
            cli.format_range('frp', 0, 512)
        self.assertIn('short reply', str(ctx.exception))

    def test_garbage_frame_magic_detected_by_device(self):
        dev = mockdevice.MockDevice()
        with self.assertRaises(mockdevice.DeviceError):
            dev.write(b'\xde\xad\xbe\xef' + b'\x00' * 60)

    def test_mock_declares_itself_as_an_assumption(self):
        self.assertIn('simulated-only', mockdevice.MockDevice.assumption)


class TestFramingEdges(unittest.TestCase):
    def test_frame_length(self):
        payload = mtk.build_format_command('frp', 0, 0)
        self.assertEqual(len(payload), mtk.PAYLOAD_LEN)
        self.assertEqual(len(mtk.frame(payload)), len(mtk.FRAME_MAGIC) + 4 + 56)

    def test_large_values_survive_roundtrip(self):
        payload = mtk.build_format_command('frp', 2 ** 30, 2 ** 30)
        cmd = mtk.parse_frame(mtk.frame(payload))
        self.assertEqual(cmd['start_value'], 2 ** 30)

    def test_parse_roundtrip(self):
        for part, sel in (('boot1', 1), ('userarea', 8), ('frp', 0)):
            cmd = mtk.parse_frame(mtk.frame(
                mtk.build_format_command(part, 7, 9)))
            self.assertEqual(cmd['partition_selector'], sel)


if __name__ == '__main__':
    unittest.main()
