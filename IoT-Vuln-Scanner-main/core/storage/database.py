# core\storage\database.py
"""
数据库操作层
统一SQLite接口
"""
import sqlite3
import logging
import json
import os
from typing import List, Dict, Optional
from datetime import datetime
from contextlib import contextmanager

logger = logging.getLogger(__name__)


class Database:
    def __init__(self, db_path: str = None):
        """
        初始化数据库连接

        Args:
            db_path: 数据库路径，如果不指定则自动使用项目根目录下的 data/devices.db
        """
        if db_path is None:
            # 自动获取项目根目录（假设 database.py 在 core/storage/ 目录下）
            # 向上回溯3层：core/storage/ -> core/ -> 项目根目录
            current_dir = os.path.dirname(os.path.abspath(__file__))
            project_root = os.path.dirname(os.path.dirname(current_dir))
            db_path = os.path.join(project_root, 'data', 'devices.db')

        self.db_path = db_path
        # 确保目录存在
        os.makedirs(os.path.dirname(self.db_path), exist_ok=True)
        self._init_tables()
        logger.info(f"数据库初始化完成: {self.db_path}")

    @contextmanager
    def _get_connection(self):
        """上下文管理器获取连接"""
        conn = sqlite3.connect(self.db_path)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def _init_tables(self):
        """初始化表结构"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            # 设备表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS devices (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    ip TEXT UNIQUE NOT NULL,
                    mac TEXT,
                    vendor TEXT,
                    device_type TEXT,
                    status TEXT DEFAULT 'unknown',
                    first_seen TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    last_scan TIMESTAMP,
                    open_ports TEXT,  -- JSON array
                    services TEXT,    -- JSON object
                    risk_score REAL DEFAULT 0.0,
                    vulnerability_count INTEGER DEFAULT 0,
                    notes TEXT
                )
            """)

            # 漏洞表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS vulnerabilities (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    device_ip TEXT,
                    cve_id TEXT,
                    title TEXT,
                    description TEXT,
                    severity TEXT,
                    cvss_score REAL,
                    solution TEXT,
                    poc_available BOOLEAN DEFAULT 0,
                    discovered_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                    status TEXT DEFAULT 'open',
                    FOREIGN KEY (device_ip) REFERENCES devices(ip),
                    UNIQUE(device_ip, cve_id)
                )
            """)

            # 扫描历史表
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS scan_history (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    scan_type TEXT,
                    target TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    devices_found INTEGER,
                    vulnerabilities_found INTEGER,
                    details TEXT
                )
            """)

            # 迁移：为已存在的表添加新列
            try:
                cursor.execute("ALTER TABLE devices ADD COLUMN vulnerability_count INTEGER DEFAULT 0")
            except sqlite3.OperationalError:
                pass

            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN solution TEXT")
            except sqlite3.OperationalError:
                pass

            try:
                cursor.execute("ALTER TABLE vulnerabilities ADD COLUMN poc_available BOOLEAN DEFAULT 0")
            except sqlite3.OperationalError:
                pass

            # 清理重复数据
            self._clean_duplicate_vulnerabilities(cursor)

            conn.commit()
            logger.info("数据库表初始化完成")

    def _clean_duplicate_vulnerabilities(self, cursor):
        """清理重复的漏洞记录，保留最新的一条"""
        try:
            cursor.execute("""
                SELECT device_ip, cve_id, COUNT(*) as cnt 
                FROM vulnerabilities 
                GROUP BY device_ip, cve_id 
                HAVING cnt > 1
            """)
            duplicates = cursor.fetchall()

            if duplicates:
                logger.warning(f"发现 {len(duplicates)} 组重复漏洞，正在清理...")
                cursor.execute("""
                    DELETE FROM vulnerabilities 
                    WHERE id NOT IN (
                        SELECT MAX(id) 
                        FROM vulnerabilities 
                        GROUP BY device_ip, cve_id
                    )
                """)
                logger.info("已清理重复漏洞")
        except Exception as e:
            logger.warning(f"清理重复漏洞时出错: {e}")

    def add_device(self, device: Dict) -> bool:
        """添加或更新设备"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                open_ports = json.dumps(device.get('open_ports', [])) if device.get('open_ports') else '[]'
                services = json.dumps(device.get('services', {})) if device.get('services') else '{}'

                cursor.execute("SELECT id FROM devices WHERE ip = ?", (device['ip'],))
                existing = cursor.fetchone()

                if existing:
                    cursor.execute("""
                        UPDATE devices SET
                            mac = ?,
                            vendor = ?,
                            device_type = ?,
                            status = ?,
                            last_scan = CURRENT_TIMESTAMP,
                            open_ports = ?,
                            services = ?,
                            risk_score = ?,
                            vulnerability_count = ?
                        WHERE ip = ?
                    """, (
                        device.get('mac'),
                        device.get('vendor'),
                        device.get('device_type'),
                        device.get('status', 'online'),
                        open_ports,
                        services,
                        device.get('risk_score', 0.0),
                        device.get('vulnerability_count', 0),
                        device['ip']
                    ))
                else:
                    cursor.execute("""
                        INSERT INTO devices 
                        (ip, mac, vendor, device_type, status, open_ports, services, risk_score, vulnerability_count)
                        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """, (
                        device['ip'],
                        device.get('mac'),
                        device.get('vendor'),
                        device.get('device_type'),
                        device.get('status', 'online'),
                        open_ports,
                        services,
                        device.get('risk_score', 0.0),
                        device.get('vulnerability_count', 0)
                    ))

                return True

        except Exception as e:
            logger.error(f"添加设备失败: {e}")
            return False

    def get_all_devices(self) -> List[Dict]:
        """获取所有设备"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT * FROM devices ORDER BY last_scan DESC")
            rows = cursor.fetchall()

            devices = []
            for row in rows:
                device = dict(row)
                open_ports = device.get('open_ports')
                services = device.get('services')

                if not open_ports:
                    device['open_ports'] = []
                else:
                    try:
                        device['open_ports'] = json.loads(open_ports)
                    except (json.JSONDecodeError, TypeError):
                        device['open_ports'] = []

                if not services:
                    device['services'] = {}
                else:
                    try:
                        device['services'] = json.loads(services)
                    except (json.JSONDecodeError, TypeError):
                        device['services'] = {}

                devices.append(device)

            return devices

    def get_vulnerable_devices(self) -> List[Dict]:
        """获取存在漏洞的设备"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT d.* FROM devices d
                JOIN vulnerabilities v ON d.ip = v.device_ip
                WHERE v.status = 'open'
                ORDER BY v.cvss_score DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def add_vulnerability(self, device_ip: str, vuln: Dict) -> bool:
        """添加漏洞记录"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT OR REPLACE INTO vulnerabilities 
                    (device_ip, cve_id, title, description, severity, cvss_score, solution, poc_available, discovered_at)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, CURRENT_TIMESTAMP)
                """, (
                    device_ip,
                    vuln.get('cve_id'),
                    vuln.get('title'),
                    vuln.get('description'),
                    vuln.get('severity'),
                    vuln.get('cvss_score', 0.0),
                    vuln.get('solution'),
                    1 if vuln.get('poc_available') else 0
                ))
                return True
        except Exception as e:
            logger.error(f"添加漏洞记录失败: {e}")
            return False

    def get_device_vulnerabilities(self, ip: str) -> List[Dict]:
        """获取设备的漏洞"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT DISTINCT * FROM vulnerabilities 
                WHERE device_ip = ? AND status = 'open'
                ORDER BY cvss_score DESC, discovered_at DESC
            """, (ip,))
            results = [dict(row) for row in cursor.fetchall()]

            for vuln in results:
                vuln['poc_available'] = bool(vuln.get('poc_available', 0))

            return results

    def update_device_risk(self, ip: str, risk_score: float, vuln_count: int = None) -> bool:
        """更新设备风险评分"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()

                if vuln_count is None:
                    cursor.execute("""
                        SELECT COUNT(DISTINCT cve_id) FROM vulnerabilities 
                        WHERE device_ip = ? AND status = 'open'
                    """, (ip,))
                    vuln_count = cursor.fetchone()[0]

                cursor.execute("""
                    UPDATE devices SET
                        risk_score = ?,
                        vulnerability_count = ?,
                        last_scan = CURRENT_TIMESTAMP
                    WHERE ip = ?
                """, (risk_score, vuln_count, ip))

                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"更新设备风险评分失败: {e}")
            return False

    def delete_device(self, ip: str) -> bool:
        """删除设备及其关联的漏洞记录"""
        try:
            with self._get_connection() as conn:
                cursor = conn.cursor()
                cursor.execute("DELETE FROM vulnerabilities WHERE device_ip = ?", (ip,))
                cursor.execute("DELETE FROM devices WHERE ip = ?", (ip,))
                return cursor.rowcount > 0
        except Exception as e:
            logger.error(f"删除设备失败: {e}")
            return False

    def log_scan(self, scan_type: str, target: str,
                 devices_found: int, vulns_found: int, details: str = ""):
        """记录扫描历史"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT INTO scan_history 
                (scan_type, target, start_time, devices_found, vulnerabilities_found, details)
                VALUES (?, ?, CURRENT_TIMESTAMP, ?, ?, ?)
            """, (scan_type, target, devices_found, vulns_found, details))

    def get_today_scans(self) -> List[Dict]:
        """获取今日扫描"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT * FROM scan_history 
                WHERE date(start_time) = date('now')
                ORDER BY start_time DESC
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_device_types_stats(self) -> List[Dict]:
        """获取设备类型统计"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT device_type, COUNT(*) as count 
                FROM devices 
                WHERE device_type IS NOT NULL
                GROUP BY device_type
            """)
            return [dict(row) for row in cursor.fetchall()]

    def get_vulnerability_trend(self, days: int = 7) -> List[Dict]:
        """获取漏洞趋势"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                SELECT date(discovered_at) as date, COUNT(*) as count
                FROM vulnerabilities
                WHERE discovered_at >= date('now', '-{} days')
                GROUP BY date(discovered_at)
                ORDER BY date
            """.format(days))
            return [dict(row) for row in cursor.fetchall()]

    def clean_old_data(self, days: int = 30):
        """清理旧数据"""
        with self._get_connection() as conn:
            cursor = conn.cursor()
            cursor.execute("""
                DELETE FROM scan_history 
                WHERE start_time < date('now', '-{} days')
            """.format(days))
            logger.info(f"清理了 {cursor.rowcount} 条旧扫描记录")

    def get_vulnerability_stats(self) -> Dict:
        """获取漏洞统计信息"""
        with self._get_connection() as conn:
            cursor = conn.cursor()

            cursor.execute("""
                SELECT severity, COUNT(*) as count 
                FROM vulnerabilities 
                WHERE status = 'open'
                GROUP BY severity
            """)
            severity_dist = {row['severity']: row['count'] for row in cursor.fetchall()}

            cursor.execute("SELECT COUNT(*) FROM vulnerabilities WHERE status = 'open'")
            total = cursor.fetchone()[0]

            cursor.execute("""
                SELECT COUNT(DISTINCT device_ip) 
                FROM vulnerabilities 
                WHERE status = 'open'
            """)
            affected_devices = cursor.fetchone()[0]

            return {
                'total': total,
                'affected_devices': affected_devices,
                'severity_distribution': severity_dist
            }