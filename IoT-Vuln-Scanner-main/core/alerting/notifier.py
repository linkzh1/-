# core\alerting\notifier.py
"""
告警通知管理器
"""
import logging
from typing import List, Dict, Optional
from dataclasses import dataclass
import json

logger = logging.getLogger(__name__)


@dataclass
class AlertMessage:
    level: str  # critical, high, medium, low
    title: str
    content: str
    device_ip: Optional[str] = None
    cve_id: Optional[str] = None
    timestamp: str = ""


class AlertNotifier:
    def __init__(self, config: Dict):
        self.channels = []
        self.config = config
        self._init_channels()

    def _init_channels(self):
        """初始化通知渠道"""
        from .channels import EmailChannel, WebhookChannel, SMSChannel

        if self.config.get('email', {}).get('enabled'):
            self.channels.append(EmailChannel(self.config['email']))

        if self.config.get('webhook', {}).get('enabled'):
            self.channels.append(WebhookChannel(self.config['webhook']))

        if self.config.get('sms', {}).get('enabled'):
            self.channels.append(SMSChannel(self.config['sms']))

    def notify(self, message: AlertMessage):
        """发送通知到所有渠道"""
        for channel in self.channels:
            try:
                channel.send(message)
            except Exception as e:
                logger.error(f"通知发送失败 ({channel.__class__.__name__}): {e}")

    def notify_critical_vulnerability(self, device: Dict, vuln: Dict):
        """高危漏洞告警"""
        msg = AlertMessage(
            level='critical',
            title=f"🚨 发现高危漏洞 {vuln.get('cve_id')}",
            content=f"""
设备: {device.get('ip')} ({device.get('vendor', 'Unknown')})
漏洞: {vuln.get('title')}
风险等级: {vuln.get('severity')}
建议: 立即隔离设备或应用补丁
            """.strip(),
            device_ip=device.get('ip'),
            cve_id=vuln.get('cve_id')
        )
        self.notify(msg)

    def notify_scan_complete(self, stats: Dict):
        """扫描完成通知"""
        msg = AlertMessage(
            level='info',
            title="✅ 扫描任务完成",
            content=f"""
扫描设备数: {stats.get('devices_scanned')}
发现漏洞数: {stats.get('vulnerabilities_found')}
高危漏洞: {stats.get('critical_count', 0)}
            """.strip()
        )
        self.notify(msg)