# core\network\arp_scanner.py
"""
ARP Scanner - 局域网设备发现
支持多线程扫描和Vendor识别
"""
import scapy.all as scapy
import ipaddress
import concurrent.futures
from typing import List, Dict, Optional
from dataclasses import dataclass
import logging

logger = logging.getLogger(__name__)


@dataclass
class Device:
    ip: str
    mac: Optional[str] = None
    vendor: Optional[str] = None
    status: str = "unknown"
    open_ports: List[int] = None

    def __post_init__(self):
        if self.open_ports is None:
            self.open_ports = []


class ARPScanner:
    def __init__(self, target_range: str, timeout: int = 2, max_workers: int = 10):
        self.target_range = target_range
        self.timeout = timeout
        self.max_workers = max_workers
        self.devices: List[Device] = []

    def scan(self) -> List[Device]:
        """执行ARP扫描"""
        try:
            network = ipaddress.ip_network(self.target_range, strict=False)
            hosts = list(network.hosts())

            logger.info(f"开始扫描网段: {self.target_range}, 共 {len(hosts)} 个IP")

            # 分批处理避免内存爆炸
            batch_size = 50
            for i in range(0, len(hosts), batch_size):
                batch = hosts[i:i + batch_size]
                self._scan_batch(batch)

            logger.info(f"扫描完成，发现 {len(self.devices)} 个设备")
            return self.devices

        except Exception as e:
            logger.error(f"扫描失败: {e}")
            return []

    def _scan_batch(self, hosts):
        """批量扫描"""
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            future_to_ip = {executor.submit(self._scan_single, str(ip)): str(ip)
                            for ip in hosts}
            for future in concurrent.futures.as_completed(future_to_ip):
                ip = future_to_ip[future]
                try:
                    device = future.result()
                    if device:
                        self.devices.append(device)
                except Exception as e:
                    logger.debug(f"扫描 {ip} 时出错: {e}")

    def _scan_single(self, ip: str) -> Optional[Device]:
        """扫描单个IP"""
        try:
            # 构造ARP请求
            arp_request = scapy.ARP(pdst=ip)
            broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
            arp_request_broadcast = broadcast / arp_request

            # 发送包
            answered_list = scapy.srp(arp_request_broadcast, timeout=self.timeout,
                                      verbose=False)[0]

            if answered_list:
                response = answered_list[0]
                mac = response[1].hwsrc
                return Device(ip=ip, mac=mac, status="online")
            return None

        except PermissionError:
            logger.error("权限不足，请使用sudo/root运行")
            raise
        except Exception as e:
            logger.debug(f"扫描 {ip} 失败: {e}")
            return None

    def get_device_by_ip(self, ip: str) -> Optional[Device]:
        """通过IP获取设备"""
        return next((d for d in self.devices if d.ip == ip), None)

    def get_device_by_mac(self, mac: str) -> Optional[Device]:
        """通过MAC获取设备"""
        return next((d for d in self.devices if d.mac and d.mac.lower() == mac.lower()), None)