# core/utils/backup.py
import shutil
import os
import sqlite3
from datetime import datetime, timedelta
from typing import List


class BackupManager:
    def __init__(self):
        self.backup_dir = 'backups'
        os.makedirs(self.backup_dir, exist_ok=True)

    def backup_database(self, db_path: str = 'data/devices.db') -> str:
        """创建数据库快照"""
        if not os.path.exists(db_path):
            return None

        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_name = f"devices_{timestamp}.db"
        backup_path = os.path.join(self.backup_dir, backup_name)

        # SQLite 在线备份（避免直接复制文件导致损坏）
        source = sqlite3.connect(db_path)
        backup = sqlite3.connect(backup_path)
        with backup:
            source.backup(backup)
        backup.close()
        source.close()

        return backup_path

    def backup_config(self, config_dir: str = 'config'):
        """备份配置文件"""
        if os.path.exists(config_dir):
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            backup_path = f"{self.backup_dir}/config_{timestamp}.zip"
            shutil.make_archive(backup_path.replace('.zip', ''), 'zip', config_dir)
            return backup_path
        return None

    def cleanup_old_backups(self, keep_days: int = 7):
        """自动清理超过7天的备份"""
        now = datetime.now()
        for filename in os.listdir(self.backup_dir):
            filepath = os.path.join(self.backup_dir, filename)
            if os.path.isfile(filepath):
                # 从文件名解析日期（假设格式：devices_20260330_143052.db）
                try:
                    date_str = filename.split('_')[1]
                    file_date = datetime.strptime(date_str, '%Y%m%d')
                    if (now - file_date).days > keep_days:
                        os.remove(filepath)
                        print(f"已清理过期备份: {filename}")
                except (IndexError, ValueError):
                    continue