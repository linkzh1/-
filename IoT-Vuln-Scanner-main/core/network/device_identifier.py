# core\network\device_identifier.py
"""
设备识别 - 基于MAC地址OUI查询
支持IEEE OUI数据库解析
"""
import re
import logging
from typing import Optional, Dict
from pathlib import Path

logger = logging.getLogger(__name__)


class DeviceIdentifier:
    def __init__(self, oui_file: str = 'data/oui.txt'):
        self.oui_file = Path(oui_file)
        self.oui_db: Dict[str, str] = {}
        self._load_oui_db()

    def _load_oui_db(self):
        """加载OUI数据库"""
        if not self.oui_file.exists():
            logger.warning(f"OUI文件不存在: {self.oui_file}")
            return

        try:
            with open(self.oui_file, 'r', encoding='utf-8', errors='ignore') as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith('#'):
                        continue

                    # 解析格式: 00-11-22   (hex)        Apple Inc.
                    match = re.match(r'^([0-9A-Fa-f]{2}[-:]){2}[0-9A-Fa-f]{2}', line)
                    if match:
                        parts = line.split(None, 2)
                        if len(parts) >= 2:
                            oui = parts[0].replace('-', ':').upper()
                            company = parts[-1].strip()
                            self.oui_db[oui] = company

            logger.info(f"加载了 {len(self.oui_db)} 条OUI记录")
        except Exception as e:
            logger.error(f"加载OUI数据库失败: {e}")

    def identify(self, mac: Optional[str]) -> str:
        """根据MAC识别厂商"""
        if not mac:
            return "Unknown"

        # 标准化MAC
        mac = mac.upper().replace('-', ':')
        if len(mac) < 8:
            return "Unknown"

        # 提取OUI (前3个字节)
        oui = mac[:8]

        return self.oui_db.get(oui, "Unknown")

    def enrich_device(self, device) -> None:
        """丰富设备信息"""
        if hasattr(device, 'mac') and device.mac:
            device.vendor = self.identify(device.mac)