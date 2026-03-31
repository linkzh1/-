# tests\test_global_stats.py
import unittest
from core.utils.global_stats import GlobalStats, NetworkStats


class TestGlobalStats(unittest.TestCase):
    def test_update_from_scan(self):
        gs = GlobalStats()
        devices = [
            {'ip': '192.168.1.1', 'status': 'online'},
            {'ip': '192.168.1.2', 'status': 'offline'},
            {'ip': '192.168.1.3', 'status': 'online'}
        ]
        vulns = [
            {'severity': 'Critical', 'device_ip': '192.168.1.1'},
            {'severity': 'High', 'device_ip': '192.168.1.1'},
            {'severity': 'Medium', 'device_ip': '192.168.1.3'}
        ]

        gs.update_from_scan(devices, vulns)

        self.assertEqual(gs.stats.total_devices, 3)
        self.assertEqual(gs.stats.online_devices, 2)
        self.assertEqual(gs.stats.high_risk_count, 2)  # Critical + High
        self.assertEqual(gs.stats.medium_risk_count, 1)
        self.assertEqual(gs.stats.vulnerable_devices, 2)  # 两个IP有漏洞

    def test_risk_distribution(self):
        gs = GlobalStats()
        gs.stats.high_risk_count = 4
        gs.stats.medium_risk_count = 2
        gs.stats.low_risk_count = 1

        dist = gs.get_risk_distribution()
        self.assertEqual(dist['High'] + dist['Critical'], 4)
        self.assertEqual(dist['Medium'], 2)
        self.assertEqual(dist['Low'], 1)


if __name__ == '__main__':
    unittest.main()