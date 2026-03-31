# core\network\enhanced_device_scanner.py
"""
增强设备扫描 - 深度指纹识别
支持服务探测和操作系统识别
"""
import socket
import concurrent.futures
from typing import List, Dict, Optional
import logging

logger = logging.getLogger(__name__)


class EnhancedDeviceScanner:
    COMMON_PORTS = [21, 22, 23, 80, 443, 554, 8080, 8443, 9100, 9200]

    def __init__(self, timeout: float = 1.0, max_workers: int = 20):
        self.timeout = timeout
        self.max_workers = max_workers

    def deep_scan(self, ip: str, ports: Optional[List[int]] = None) -> Dict:
        """深度扫描设备"""
        if ports is None:
            ports = self.COMMON_PORTS

        result = {
            'ip': ip,
            'open_ports': [],
            'services': {},
            'os_guess': None,
            'device_type': None
        }

        # 端口扫描
        open_ports = self._scan_ports(ip, ports)
        result['open_ports'] = open_ports

        # 服务识别
        for port in open_ports:
            service = self._identify_service(ip, port)
            if service:
                result['services'][port] = service

        # 设备类型推断
        result['device_type'] = self._guess_device_type(result['services'])

        return result

    def _scan_ports(self, ip: str, ports: List[int]) -> List[int]:
        """TCP端口扫描"""
        open_ports = []

        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_port = {executor.submit(self._check_port, ip, port): port
                              for port in ports}
            for future in concurrent.futures.as_completed(future_to_port):
                port = future_to_port[future]
                try:
                    if future.result():
                        open_ports.append(port)
                except Exception:
                    pass

        return sorted(open_ports)

    def _check_port(self, ip: str, port: int) -> bool:
        """检查单个端口"""
        try:
            with socket.create_connection((ip, port), timeout=self.timeout):
                return True
        except (socket.timeout, ConnectionRefusedError, OSError):
            return False

    def _identify_service(self, ip: str, port: int) -> Optional[Dict]:
        """识别服务类型和版本"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(self.timeout)
            sock.connect((ip, port))

            # 尝试获取banner
            banner = ""
            try:
                if port == 80 or port == 8080:
                    sock.send(b"HEAD / HTTP/1.0\r\n\r\n")
                banner = sock.recv(1024).decode('utf-8', errors='ignore').strip()
            except:
                pass

            sock.close()

            # 服务识别逻辑
            service_guess = self._guess_service(port, banner)

            return {
                'port': port,
                'banner': banner[:200],  # 截断避免过长
                'service': service_guess,
                'protocol': 'tcp'
            }

        except Exception as e:
            logger.debug(f"识别服务失败 {ip}:{port}: {e}")
            return None

    def _guess_service(self, port: int, banner: str) -> str:
        """根据端口和banner猜测服务"""
        port_map = {
            21: 'FTP', 22: 'SSH', 23: 'Telnet', 80: 'HTTP', 443: 'HTTPS',
            554: 'RTSP', 8080: 'HTTP-Proxy', 8443: 'HTTPS-Alt', 9100: 'Raw-Print'
        }

        # 基于banner的精细识别
        if 'SSH' in banner:
            return 'SSH'
        elif 'HTTP' in banner or 'html' in banner.lower():
            return 'HTTP'
        elif 'FTP' in banner:
            return 'FTP'

        return port_map.get(port, f'Unknown-{port}')

    def _guess_device_type(self, services: Dict) -> Optional[str]:
        """根据开放服务猜测设备类型"""
        ports = set(services.keys())

        if 554 in ports or 8554 in ports:
            return "IP-Camera/NVR"
        elif 9100 in ports or 631 in ports:
            return "Printer"
        elif 22 in ports and 80 in ports and len(ports) > 3:
            return "Router/Gateway"
        elif 53 in ports or 67 in ports:
            return "Network-Device"
        elif len(ports) > 5:
            return "Computer/Server"

        return "IoT-Device"