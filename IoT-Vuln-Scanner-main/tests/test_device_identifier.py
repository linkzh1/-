# tests\test_device_identifier.py
import unittest
import tempfile
import os
from core.network.device_identifier import DeviceIdentifier


class TestDeviceIdentifier(unittest.TestCase):
    def setUp(self):
        self.temp_oui = tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.txt')
        self.temp_oui.write("00-50-56   VMware\n")
        self.temp_oui.write("00-1B-21   IntelCorp\n")
        self.temp_oui.write("BC-5C-4C   Apple\n")
        self.temp_oui.close()
        self.identifier = DeviceIdentifier(self.temp_oui.name)

    def tearDown(self):
        os.unlink(self.temp_oui.name)

    def test_vmware_identification(self):
        mac = "00:50:56:12:34:56"
        vendor = self.identifier.identify(mac)
        self.assertEqual(vendor, "VMware")

    def test_apple_identification(self):
        mac = "BC:5C:4C:AA:BB:CC"
        vendor = self.identifier.identify(mac)
        self.assertEqual(vendor, "Apple")

    def test_unknown_device(self):
        mac = "FF:FF:FF:11:22:33"
        vendor = self.identifier.identify(mac)
        self.assertEqual(vendor, "Unknown")

    def test_mac_format_variations(self):
        # 测试不同格式的MAC（冒号和横线）
        mac1 = "00-1B-21-44-55-66"
        mac2 = "00:1b:21:44:55:66"
        self.assertEqual(self.identifier.identify(mac1), "IntelCorp")
        self.assertEqual(self.identifier.identify(mac2), "IntelCorp")


if __name__ == '__main__':
    unittest.main()