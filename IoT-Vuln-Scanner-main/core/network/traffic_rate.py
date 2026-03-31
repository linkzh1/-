# core\network\traffic_rate.py
"""
流量分析 - 实时监控和统计
"""
import psutil
import time
from collections import defaultdict
from dataclasses import dataclass
from typing import Dict, List
import threading


@dataclass
class TrafficStats:
    timestamp: float
    bytes_sent: int
    bytes_recv: int
    packets_sent: int
    packets_recv: int
    connections: int


class TrafficMonitor:
    def __init__(self, interval: int = 5):
        self.interval = interval
        self.history: List[TrafficStats] = []
        self.device_stats = defaultdict(lambda: {'in': 0, 'out': 0})
        self._running = False
        self._thread = None
        self._lock = threading.Lock()

    def start_monitoring(self):
        """启动后台监控线程"""
        if self._running:
            return

        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop_monitoring(self):
        """停止监控"""
        self._running = False
        if self._thread:
            self._thread.join()

    def _monitor_loop(self):
        """监控循环"""
        old_io = psutil.net_io_counters()

        while self._running:
            time.sleep(self.interval)

            new_io = psutil.net_io_counters()
            connections = len(psutil.net_connections())

            stat = TrafficStats(
                timestamp=time.time(),
                bytes_sent=new_io.bytes_sent - old_io.bytes_sent,
                bytes_recv=new_io.bytes_recv - old_io.bytes_recv,
                packets_sent=new_io.packets_sent - old_io.packets_sent,
                packets_recv=new_io.packets_recv - old_io.packets_recv,
                connections=connections
            )

            with self._lock:
                self.history.append(stat)
                # 保留最近100条记录
                if len(self.history) > 100:
                    self.history.pop(0)

            old_io = new_io

    def get_current_stats(self) -> Dict:
        """获取当前统计"""
        if not self.history:
            return {}

        with self._lock:
            latest = self.history[-1]

        return {
            'upload_speed_bps': (latest.bytes_sent * 8) / self.interval,
            'download_speed_bps': (latest.bytes_recv * 8) / self.interval,
            'total_connections': latest.connections,
            'packets_sent': latest.packets_sent,
            'packets_recv': latest.packets_recv
        }

    def get_history(self, count: int = 20) -> List[Dict]:
        """获取历史记录"""
        with self._lock:
            history = self.history[-count:]

        return [
            {
                'timestamp': h.timestamp,
                'upload_mbps': (h.bytes_sent * 8) / (1024 * 1024 * self.interval),
                'download_mbps': (h.bytes_recv * 8) / (1024 * 1024 * self.interval)
            }
            for h in history
        ]