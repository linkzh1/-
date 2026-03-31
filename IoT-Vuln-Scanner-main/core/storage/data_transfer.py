# core\storage\data_transfer.py
"""
数据传输模块
支持导入导出、备份恢复
"""
import json
import csv
import shutil
import logging
from pathlib import Path
from typing import List, Dict
from datetime import datetime

logger = logging.getLogger(__name__)


class DataTransfer:
    def __init__(self, db_path: str = 'data/devices.db'):
        self.db_path = db_path

    def export_to_json(self, output_file: str,
                       include_vulns: bool = True) -> bool:
        """导出所有数据为JSON"""
        try:
            from core.storage.database import Database
            db = Database(self.db_path)

            data = {
                'export_time': datetime.now().isoformat(),
                'version': '2.0',
                'devices': db.get_all_devices()
            }

            if include_vulns:
                data['vulnerabilities'] = []
                for device in data['devices']:
                    vulns = db.get_device_vulnerabilities(device['ip'])
                    data['vulnerabilities'].extend(vulns)

            with open(output_file, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False, default=str)

            logger.info(f"数据已导出到: {output_file}")
            return True

        except Exception as e:
            logger.error(f"导出失败: {e}")
            return False

    def export_to_csv(self, output_file: str) -> bool:
        """导出为CSV"""
        try:
            from core.storage.database import Database
            db = Database(self.db_path)
            devices = db.get_all_devices()

            with open(output_file, 'w', newline='', encoding='utf-8') as f:
                writer = csv.writer(f)
                writer.writerow(['IP', 'MAC', 'Vendor', 'Type', 'Status',
                                 'Open Ports', 'Risk Score'])

                for d in devices:
                    writer.writerow([
                        d['ip'], d['mac'], d['vendor'],
                        d.get('device_type', 'Unknown'),
                        d['status'],
                        len(d.get('open_ports', [])),
                        d.get('risk_score', 0)
                    ])

            return True
        except Exception as e:
            logger.error(f"CSV导出失败: {e}")
            return False

    def import_from_json(self, input_file: str) -> bool:
        """从JSON导入数据"""
        try:
            with open(input_file, 'r', encoding='utf-8') as f:
                data = json.load(f)

            from core.storage.database import Database
            db = Database(self.db_path)

            for device in data.get('devices', []):
                db.add_device(device)

            for vuln in data.get('vulnerabilities', []):
                db.add_vulnerability(vuln.get('device_ip'), vuln)

            logger.info(f"导入了 {len(data.get('devices', []))} 个设备")
            return True

        except Exception as e:
            logger.error(f"导入失败: {e}")
            return False

    def backup_database(self, backup_dir: str = 'backups/') -> str:
        """备份数据库"""
        Path(backup_dir).mkdir(exist_ok=True)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_path = f"{backup_dir}/devices_backup_{timestamp}.db"

        try:
            shutil.copy2(self.db_path, backup_path)
            logger.info(f"数据库已备份到: {backup_path}")
            return backup_path
        except Exception as e:
            logger.error(f"备份失败: {e}")
            return ""