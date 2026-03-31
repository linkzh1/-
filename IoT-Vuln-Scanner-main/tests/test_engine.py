# tests\test_engine.py
import unittest
import sys
import os

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.vulnerability.scanner.engine import ScanEngine, ScanTask, ScanStatus

class TestScanEngine(unittest.TestCase):
    """扫描引擎核心测试（毕设答辩演示用）"""

    def setUp(self):
        self.engine = ScanEngine(max_workers=5, timeout=10)

    def test_mock_vulnerability_injection(self):
        """
        测试虚拟漏洞注入功能（毕设关键演示点）
        验证：192.168.31.x网段能触发测试数据注入
        """
        # 测试IP触发虚拟数据注入
        device_info = {
            'ip': '192.168.31.100',
            'mac': '00:11:22:33:44:55',
            'open_ports': [80, 8080]
        }

        result = self.engine.scan_device(device_info)

        # 验证注入的漏洞数量
        self.assertGreaterEqual(len(result['vulnerabilities']), 1,
                                "应至少注入1个CVE漏洞")

        # 验证严重程度分布
        severities = [v['severity'] for v in result['vulnerabilities']]
        self.assertIn('Critical', severities, "应包含Critical级别漏洞")
        self.assertIn('High', severities, "应包含High级别漏洞")

        # 验证认证漏洞注入
        self.assertGreaterEqual(len(result['auth_issues']), 1,
                                "应注入认证漏洞")

        # 验证协议漏洞注入
        self.assertGreaterEqual(len(result['protocol_issues']), 1,
                                "应注入协议漏洞")

    def test_risk_score_calculation(self):
        """测试风险评分算法（封顶10分）"""
        test_cases = [
            # (漏洞列表, 期望分数)
            ([{'severity': 'Critical'}], 10),
            ([{'severity': 'Critical'}, {'severity': 'High'}], 10),  # 封顶
            ([{'severity': 'High'}, {'severity': 'High'}], 10),  # 7+7=14→封顶10
            ([{'severity': 'High'}], 7),
            ([{'severity': 'Medium'}], 4),
            ([{'severity': 'Low'}], 1),
            ([], 0),  # 无漏洞
            ([{'severity': 'Medium'}, {'severity': 'Low'}], 5),  # 4+1=5
        ]

        for vulns, expected in test_cases:
            with self.subTest(vulns=vulns):
                score = min(
                    sum({'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1}.get(
                        v['severity'], 0) for v in vulns), 10
                )
                self.assertEqual(score, expected,
                                 f"漏洞{[v['severity'] for v in vulns]}期望分数{expected}，实际{score}")

    def test_device_info_compatibility(self):
        """测试参数兼容性：支持字符串IP和字典"""
        # 字符串IP（旧版兼容）
        result1 = self.engine.scan_device('127.0.0.1')
        self.assertEqual(result1['ip'], '127.0.0.1')

        # 字典（新版）
        result2 = self.engine.scan_device({
            'ip': '192.168.1.1',
            'mac': 'aa:bb:cc:dd:ee:ff'
        })
        self.assertEqual(result2['mac'], 'aa:bb:cc:dd:ee:ff')

    def test_scan_task_lifecycle(self):
        """测试扫描任务状态流转"""
        task = ScanTask(
            target='192.168.1.1',
            task_type='port',
            priority=1
        )

        self.assertEqual(task.status, ScanStatus.PENDING)

        # 模拟任务执行
        task.status = ScanStatus.RUNNING
        self.assertEqual(task.status, ScanStatus.RUNNING)

        task.status = ScanStatus.COMPLETED
        self.assertEqual(task.status, ScanStatus.COMPLETED)


class TestEngineIntegration(unittest.TestCase):
    """集成测试：使用mock数据测试完整流程"""

    def test_with_mock_arp_data(self):
        """使用mock_arp_output.py的数据测试"""
        from tests.mock_arp_output import mock_arp_output

        engine = ScanEngine()
        device = mock_arp_output[0]  # Samsung Smart TV

        # 转换格式
        device_info = {
            'ip': device['ip_address'],
            'mac': device['mac_address'],
            'device_type': device['device_type'],
            'open_ports': [80]  # 模拟开放端口
        }

        result = engine.scan_device(device_info)

        # 验证返回结构完整
        self.assertIn('vulnerabilities', result)
        self.assertIn('auth_issues', result)
        self.assertIn('protocol_issues', result)
        self.assertIn('open_ports', result)


if __name__ == '__main__':
    unittest.main()