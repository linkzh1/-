# core\remediation\advisor.py
"""
修复建议生成器
根据漏洞自动生成修复方案
"""
import logging
from typing import Dict, List, Optional
from dataclasses import dataclass

logger = logging.getLogger(__name__)


@dataclass
class RemediationStep:
    priority: int  # 1-5，1最高
    action: str
    details: str
    risk: str  # 'low', 'medium', 'high' - 执行风险
    automated: bool
    command: Optional[str] = None


class RemediationAdvisor:
    def __init__(self):
        self.knowledge_base = self._load_knowledge_base()

    def _load_knowledge_base(self) -> Dict:
        """加载修复知识库"""
        return {
            'CVE-2021-XXXX': {
                'type': 'firmware',
                'steps': [
                    RemediationStep(1, '固件升级', '升级到v2.1+', 'low', False),
                    RemediationStep(2, '访问限制', '限制管理接口IP', 'low', True,
                                    'iptables -A INPUT -p tcp --dport 80 -s 192.168.1.0/24 -j ACCEPT')
                ]
            },
            'default_password': {
                'type': 'config',
                'steps': [
                    RemediationStep(1, '修改默认密码', '更换强密码', 'low', False),
                    RemediationStep(2, '启用账户锁定', '失败3次锁定15分钟', 'low', True, 'faillock -- deny=3 unlock_time=900')
                ]
            },
            'telnet_enabled': {
                'type': 'service',
                'steps': [
                    RemediationStep(1, '禁用Telnet', '停止并禁用服务', 'medium', True,
                                    'systemctl stop telnet && systemctl disable telnet'),
                    RemediationStep(2, '启用SSH', '配置密钥认证', 'low', False)
                ]
            },
            'weak_crypto': {
                'type': 'config',
                'steps': [
                    RemediationStep(1, '禁用SSLv2/3', '更新加密配置', 'medium', True, 'ssl_protocols TLSv1.2 TLSv1.3;'),
                    RemediationStep(2, '更新证书', '使用2048位+ RSA', 'low', False)
                ]
            }
        }

    def get_remediation(self, vulnerability: Dict) -> List[RemediationStep]:
        """获取修复步骤"""
        cve_id = vulnerability.get('cve_id', '')

        # 精确匹配
        if cve_id in self.knowledge_base:
            return self.knowledge_base[cve_id]['steps']

        # 模糊匹配
        if 'default' in cve_id.lower() or 'password' in vulnerability.get('title', '').lower():
            return self.knowledge_base['default_password']['steps']

        if 'telnet' in vulnerability.get('title', '').lower():
            return self.knowledge_base['telnet_enabled']['steps']

        if 'ssl' in vulnerability.get('title', '').lower() or 'tls' in vulnerability.get('title', '').lower():
            return self.knowledge_base['weak_crypto']['steps']

        # 通用建议
        return [
            RemediationStep(1, '研究补丁', f'查找{cve_id}的官方补丁', 'low', False),
            RemediationStep(2, '网络隔离', '将设备移至隔离VLAN', 'medium', True, None),
            RemediationStep(3, '监控流量', '增加对该设备的流量监控', 'low', True, None)
        ]

    def generate_report(self, device_ip: str, vulnerabilities: List[Dict]) -> Dict:
        """生成完整修复报告"""
        all_steps = []
        for vuln in vulnerabilities:
            steps = self.get_remediation(vuln)
            all_steps.extend([(s, vuln) for s in steps])

        # 按优先级排序
        all_steps.sort(key=lambda x: x[0].priority)

        return {
            'device': device_ip,
            'total_vulns': len(vulnerabilities),
            'immediate_actions': [s for s, v in all_steps if s.priority == 1],
            'short_term': [s for s, v in all_steps if s.priority == 2],
            'long_term': [s for s, v in all_steps if s.priority >= 3],
            'estimated_fix_time': len(vulnerabilities) * 30  # 分钟
        }