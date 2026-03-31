# tests\test_anonymization.py
import unittest
from core.privacy.anonymization import Anonymizer, PrivacyConfig, ConsentManager
import os
import tempfile


class TestAnonymization(unittest.TestCase):
    def setUp(self):
        self.config = PrivacyConfig(enable_anonymization=True)
        self.anonymizer = Anonymizer(self.config)

    def test_ip_masking_partial(self):
        ip = "192.168.1.100"
        masked = self.anonymizer.mask_ip(ip)
        self.assertEqual(masked, "192.168.***.100")

    def test_ip_masking_full(self):
        self.config.ip_mask_level = 'full'
        ip = "192.168.1.100"
        masked = self.anonymizer.mask_ip(ip)
        self.assertEqual(masked, "***.***.***.100")

    def test_mac_masking(self):
        mac = "00:11:22:33:44:55"
        masked = self.anonymizer.mask_mac(mac)
        self.assertTrue("XX" in masked)  # 只要有脱敏标记即可
        self.assertTrue("00:11:22" in masked)  # OUI保留

    def test_device_anonymization(self):
        device = {
            'ip': '192.168.1.1',
            'mac': '00:11:22:33:44:55',
            'vendor': 'Apple',
            'open_ports': [80, 443]
        }
        anon = self.anonymizer.anonymize_device_data(device)
        self.assertNotEqual(anon['ip'], '192.168.1.1')
        self.assertNotEqual(anon['mac'], '00:11:22:33:44:55')
        self.assertEqual(anon['vendor'], 'Apple')  # 厂商不脱敏
        self.assertIn('anon_id', anon)

    def test_consent_manager(self):
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as f:
            f.write('{}')
            temp_file = f.name

        try:
            cm = ConsentManager(temp_file)
            cm.record_consent('user1', 'data_collection', True)
            self.assertTrue(cm.check_consent('user1'))

            cm.withdraw_consent('user1')
            self.assertFalse(cm.check_consent('user1'))
        finally:
            os.unlink(temp_file)


if __name__ == '__main__':
    unittest.main()