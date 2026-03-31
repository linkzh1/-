# core\privacy\anonymization.py
"""
数据匿名化与隐私管理
符合GDPR/个人信息保护法要求
"""
import re
import hashlib
import logging
from typing import Dict, Any, Optional, Union
from dataclasses import dataclass
from datetime import datetime, timedelta
import json

logger = logging.getLogger(__name__)


@dataclass
class PrivacyConfig:
    enable_anonymization: bool = True
    ip_mask_level: str = 'partial'  # 'full', 'partial', 'none'
    mac_mask_level: str = 'partial'  # 'full', 'partial', 'none'
    retention_days: int = 30
    allow_analytics: bool = True


class Anonymizer:
    def __init__(self, config: Optional[PrivacyConfig] = None):
        self.config = config or PrivacyConfig()
        self.salt = self._generate_salt()

    def _generate_salt(self) -> str:
        """生成盐值用于哈希"""
        import secrets
        return secrets.token_hex(16)

    def mask_ip(self, ip: str) -> str:
        """IP地址掩码"""
        if not self.config.enable_anonymization or self.config.ip_mask_level == 'none':
            return ip

        try:
            if '.' in ip:  # IPv4
                parts = ip.split('.')
                if self.config.ip_mask_level == 'full':
                    return '***.***.***.' + parts[3]
                else:  # partial
                    return f"{parts[0]}.{parts[1]}.***.{parts[3]}"
            else:  # IPv6
                if self.config.ip_mask_level == 'full':
                    return ip.split(':')[-1] + ':***'
                return ip[:9] + '****:****:****:' + ip.split(':')[-1]
        except:
            return "***.***.***.***"

    def mask_mac(self, mac: str) -> str:
        """MAC地址掩码"""
        if not self.config.enable_anonymization or self.config.mac_mask_level == 'none':
            return mac

        mac = mac.upper().replace('-', ':')
        parts = mac.split(':')

        if len(parts) != 6:
            return "XX:XX:XX:XX:XX:XX"

        if self.config.mac_mask_level == 'full':
            # 保留厂商标识(OUI)，隐藏设备标识
            return f"{parts[0]}:{parts[1]}:{parts[2]}:XX:XX:XX"
        else:  # partial - 保留完整OUI(前三段)，部分隐藏后三段
            return f"{parts[0]}:{parts[1]}:{parts[2]}:**:XX:{parts[5]}"

    def hash_id(self, identifier: str) -> str:
        """生成不可逆哈希ID"""
        return hashlib.sha256(f"{identifier}{self.salt}".encode()).hexdigest()[:16]

    def anonymize_device_data(self, device: Union[Dict, Any]) -> Dict:
        """匿名化设备数据"""
        if not self.config.enable_anonymization:
            return device if isinstance(device, dict) else vars(device)

        # 创建副本
        if isinstance(device, dict):
            anon = device.copy()
        else:
            anon = vars(device).copy() if hasattr(device, '__dict__') else {}

        # 处理IP
        if 'ip' in anon:
            anon['ip'] = self.mask_ip(anon['ip'])

        # 处理MAC
        if 'mac' in anon:
            anon['mac'] = self.mask_mac(anon['mac'])

        # 生成匿名ID用于关联分析
        if 'ip' in device and 'mac' in device:
            anon['anon_id'] = self.hash_id(f"{device['ip']}{device['mac']}")

        return anon

    def anonymize_scan_result(self, result: Dict) -> Dict:
        """匿名化扫描结果"""
        if not self.config.enable_anonymization:
            return result

        anon_result = result.copy()

        # 匿名化设备信息
        if 'devices' in anon_result:
            anon_result['devices'] = [
                self.anonymize_device_data(d) for d in anon_result['devices']
            ]

        # 移除原始识别符
        if 'raw_packets' in anon_result:
            del anon_result['raw_packets']

        return anon_result


class ConsentManager:
    """用户隐私同意管理"""

    def __init__(self, consent_file: str = 'config/consent.json'):
        self.consent_file = consent_file
        self.consents = self._load_consents()

    def _load_consents(self) -> Dict:
        """加载同意记录"""
        try:
            with open(self.consent_file, 'r') as f:
                return json.load(f)
        except:
            return {}

    def _save_consents(self):
        """保存同意记录"""
        with open(self.consent_file, 'w') as f:
            json.dump(self.consents, f, indent=2)

    def record_consent(self, user_id: str, purpose: str,
                       granted: bool, metadata: Dict = None):
        """记录用户同意"""
        self.consents[user_id] = {
            'purpose': purpose,
            'granted': granted,
            'timestamp': datetime.now().isoformat(),
            'metadata': metadata or {},
            'expiry': (datetime.now() + timedelta(days=365)).isoformat()
        }
        self._save_consents()

    def check_consent(self, user_id: str) -> bool:
        """检查用户是否同意"""
        consent = self.consents.get(user_id)
        if not consent:
            return False

        # 检查是否过期
        expiry = datetime.fromisoformat(consent.get('expiry', '2000-01-01'))
        if datetime.now() > expiry:
            return False

        return consent.get('granted', False)

    def withdraw_consent(self, user_id: str):
        """撤销同意"""
        if user_id in self.consents:
            self.consents[user_id]['granted'] = False
            self.consents[user_id]['withdrawn_at'] = datetime.now().isoformat()
            self._save_consents()