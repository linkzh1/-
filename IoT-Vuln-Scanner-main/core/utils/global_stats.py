# core\utils\global_stats.py
"""
全局统计数据维护
"""
import logging
from typing import Dict, List
from dataclasses import dataclass, asdict
import json

logger = logging.getLogger(__name__)


@dataclass
class NetworkStats:
    total_devices: int = 0
    online_devices: int = 0
    vulnerable_devices: int = 0
    high_risk_count: int = 0
    medium_risk_count: int = 0
    low_risk_count: int = 0
    last_update: str = ""


class GlobalStats:
    def __init__(self):
        self.stats = NetworkStats()

    def update_from_scan(self, devices: List[Dict],
                         vulnerabilities: List[Dict]):
        """根据扫描结果更新统计"""
        self.stats.total_devices = len(devices)
        self.stats.online_devices = len([d for d in devices if d.get('status') == 'online'])

        # 风险统计
        vuln_counts = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}
        vulnerable_ips = set()

        for vuln in vulnerabilities:
            sev = vuln.get('severity', 'Low')
            if sev in vuln_counts:
                vuln_counts[sev] += 1
            vulnerable_ips.add(vuln.get('device_ip'))

        self.stats.vulnerable_devices = len(vulnerable_ips)
        self.stats.high_risk_count = vuln_counts['Critical'] + vuln_counts['High']
        self.stats.medium_risk_count = vuln_counts['Medium']
        self.stats.low_risk_count = vuln_counts['Low']

        from datetime import datetime
        self.stats.last_update = datetime.now().isoformat()

    def to_dict(self) -> Dict:
        return asdict(self.stats)

    def get_risk_distribution(self) -> Dict[str, int]:
        """获取风险分布"""
        return {
            'Critical': self.stats.high_risk_count // 2,  # 简化计算
            'High': self.stats.high_risk_count - self.stats.high_risk_count // 2,
            'Medium': self.stats.medium_risk_count,
            'Low': self.stats.low_risk_count
        }