# core\reporting\report_data.py
import sqlite3
import json
from datetime import datetime
from typing import List, Dict, Optional
from dataclasses import dataclass


@dataclass
class VulnerabilityItem:
    cve_id: str
    severity: str  # Critical, High, Medium, Low
    title: str
    description: str
    poc_result: Optional[str]
    remediation: str


@dataclass
class DeviceReport:
    ip: str
    mac: str
    vendor: str
    device_type: str
    open_ports: List[int]
    vulnerabilities: List[VulnerabilityItem]
    risk_score: float  # 0-10


class ReportDataCollector:
    def __init__(self, db_path: str = "data/devices.db"):
        self.db_path = db_path

    def get_scan_report(self, scan_id: Optional[str] = None) -> Dict:
        """
        聚合扫描数据用于PDF报告
        如果不传scan_id，取最近一次扫描
        """
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row

        # 获取扫描基础信息
        cursor = conn.execute("""
            SELECT scan_time, network_range, total_devices 
            FROM scan_history 
            WHERE scan_id = ? OR scan_id = (SELECT MAX(scan_id) FROM scan_history)
            LIMIT 1
        """, (scan_id,))
        scan_info = dict(cursor.fetchone())

        # 获取设备详情（关联漏洞）
        devices = []
        cursor = conn.execute("""
            SELECT d.ip, d.mac, d.vendor, d.device_type, d.open_ports,
                   v.cve_id, v.severity, v.title, v.description, v.remediation
            FROM devices d
            LEFT JOIN vulnerabilities v ON d.device_id = v.device_id
            WHERE d.scan_id = ?
            ORDER BY d.ip, v.severity
        """, (scan_id,))

        # 聚合设备-漏洞关系
        device_map = {}
        for row in cursor.fetchall():
            ip = row['ip']
            if ip not in device_map:
                device_map[ip] = {
                    'ip': ip,
                    'mac': row['mac'],
                    'vendor': row['vendor'],
                    'type': row['device_type'],
                    'ports': json.loads(row['open_ports']) if row['open_ports'] else [],
                    'vulns': []
                }
            if row['cve_id']:
                device_map[ip]['vulns'].append({
                    'cve': row['cve_id'],
                    'severity': row['severity'],
                    'title': row['title'],
                    'description': row['description'],
                    'remediation': row['remediation']
                })

        # 计算统计数据
        stats = self._calculate_stats(device_map)

        conn.close()

        return {
            'generated_at': datetime.now().strftime("%Y-%m-%d %H:%M"),
            'scan_info': scan_info,
            'devices': list(device_map.values()),
            'statistics': stats
        }

    def _calculate_stats(self, device_map: Dict) -> Dict:
        """计算风险统计数据"""
        total_vulns = sum(len(d['vulns']) for d in device_map.values())
        severity_count = {'Critical': 0, 'High': 0, 'Medium': 0, 'Low': 0}

        for device in device_map.values():
            for vuln in device['vulns']:
                sev = vuln['severity']
                if sev in severity_count:
                    severity_count[sev] += 1

        # 计算风险评分（简单算法）
        risk_score = (
                             severity_count['Critical'] * 10 +
                             severity_count['High'] * 5 +
                             severity_count['Medium'] * 2 +
                             severity_count['Low'] * 0.5
                     ) / max(len(device_map), 1)

        return {
            'total_devices': len(device_map),
            'total_vulnerabilities': total_vulns,
            'severity_distribution': severity_count,
            'average_risk_score': round(min(risk_score, 10), 2),
            'compliant_devices': len([d for d in device_map.values() if not d['vulns']])
        }