# config/settings.py
"""
全局配置管理
"""
import os
from dataclasses import dataclass
from typing import Optional


@dataclass
class ScanConfig:
    timeout: int = 5
    max_threads: int = 10
    default_ports = [21, 22, 23, 80, 443, 554, 8080, 8443]
    enable_poc: bool = True
    enable_auth_check: bool = True


@dataclass
class PrivacyConfig:
    enable_anonymization: bool = True
    mask_ip: bool = True
    mask_mac: bool = True
    data_retention_days: int = 30


@dataclass
class AlertConfig:
    email_enabled: bool = False
    smtp_server: str = ""
    smtp_port: int = 587
    username: str = ""
    password: str = ""
    to_emails: list = None

    webhook_enabled: bool = False
    webhook_url: str = ""


class Settings:
    def __init__(self):
        self.scan = ScanConfig()
        self.privacy = PrivacyConfig()
        self.alert = AlertConfig()
        self._load_env()

    def _load_env(self):
        """从环境变量加载配置"""
        if os.getenv('SCAN_TIMEOUT'):
            self.scan.timeout = int(os.getenv('SCAN_TIMEOUT'))
        if os.getenv('SMTP_SERVER'):
            self.alert.email_enabled = True
            self.alert.smtp_server = os.getenv('SMTP_SERVER')
            self.alert.username = os.getenv('SMTP_USER', '')
            self.alert.password = os.getenv('SMTP_PASS', '')


# 全局实例
settings = Settings()