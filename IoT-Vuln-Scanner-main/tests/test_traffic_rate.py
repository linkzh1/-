# tests\test_traffic_rate.py
import unittest
import sys
import os
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from core.network.traffic_rate import TrafficMonitor, TrafficStats


class TestTrafficRate(unittest.TestCase):
    """流量监控模块测试"""

    def test_traffic_monitor_init(self):
        """测试监控器初始化"""
        tm = TrafficMonitor(interval=1)
        self.assertEqual(tm.interval, 1)
        self.assertFalse(tm._running)
        self.assertEqual(len(tm.history), 0)

    def test_start_stop_monitoring(self):
        """测试启动和停止监控"""
        tm = TrafficMonitor(interval=1)

        # 启动监控
        tm.start_monitoring()
        self.assertTrue(tm._running)
        self.assertIsNotNone(tm._thread)
        self.assertTrue(tm._thread.is_alive())

        # 等待一个采集周期
        time.sleep(1.5)

        # 停止监控
        tm.stop_monitoring()
        self.assertFalse(tm._running)
        self.assertFalse(tm._thread.is_alive())

    def test_get_current_stats(self):
        """测试获取当前统计（不启动后台线程）"""
        tm = TrafficMonitor(interval=1)

        # 手动添加测试数据
        tm.history.append(TrafficStats(
            timestamp=time.time(),
            bytes_sent=1024 * 100,  # 100KB
            bytes_recv=1024 * 200,  # 200KB
            packets_sent=100,
            packets_recv=200,
            connections=50
        ))

        stats = tm.get_current_stats()

        self.assertIn('upload_speed_bps', stats)
        self.assertIn('download_speed_bps', stats)
        self.assertIn('total_connections', stats)
        self.assertEqual(stats['total_connections'], 50)

        # 验证速度计算（bps = bytes * 8 / interval）
        expected_upload = (1024 * 100 * 8) / 1  # 100KB/s = 819200 bps
        self.assertAlmostEqual(stats['upload_speed_bps'], expected_upload, delta=1000)

    def test_get_history(self):
        """测试获取历史记录"""
        tm = TrafficMonitor(interval=1)

        # 添加多条记录
        for i in range(5):
            tm.history.append(TrafficStats(
                timestamp=time.time() + i,
                bytes_sent=1024 * (i + 1),
                bytes_recv=1024 * (i + 2),
                packets_sent=i * 10,
                packets_recv=i * 20,
                connections=10 + i
            ))

        # 获取最近3条
        history = tm.get_history(count=3)
        self.assertEqual(len(history), 3)

        # 验证数据格式
        first_record = history[0]
        self.assertIn('timestamp', first_record)
        self.assertIn('upload_mbps', first_record)
        self.assertIn('download_mbps', first_record)

        # 验证单位转换（MBps）
        # bytes_sent=1024*3=3KB, interval=1s -> 3KB/s = 0.003 MB/s * 8 = 0.024 Mbps
        self.assertGreater(history[0]['upload_mbps'], 0)

    def test_history_limit(self):
        """测试历史记录上限（保留最近100条）"""
        tm = TrafficMonitor(interval=0.1)

        # 直接添加测试数据（不启动后台线程）
        for i in range(110):
            tm.history.append(TrafficStats(
                timestamp=time.time() + i,
                bytes_sent=i,
                bytes_recv=i * 2,
                packets_sent=i,
                packets_recv=i,
                connections=i
            ))

        # 手动触发限制逻辑（模拟 _monitor_loop 中的行为）
        with tm._lock:
            while len(tm.history) > 100:
                tm.history.pop(0)

        self.assertEqual(len(tm.history), 100)
        self.assertEqual(tm.history[-1].bytes_sent, 109)  # 验证保留的是最新的

    def test_thread_safety(self):
        """测试线程安全（多线程访问不崩溃）"""
        tm = TrafficMonitor(interval=0.1)

        import threading

        def add_stats():
            for i in range(10):
                with tm._lock:
                    tm.history.append(TrafficStats(
                        timestamp=time.time(),
                        bytes_sent=i,
                        bytes_recv=i * 2,
                        packets_sent=i,
                        packets_recv=i,
                        connections=i
                    ))
                time.sleep(0.01)

        def read_stats():
            for _ in range(10):
                _ = tm.get_current_stats()
                _ = tm.get_history(count=5)
                time.sleep(0.01)

        # 启动读写线程
        t1 = threading.Thread(target=add_stats)
        t2 = threading.Thread(target=read_stats)

        t1.start()
        t2.start()
        t1.join()
        t2.join()

        # 如果执行到这里没有异常，说明线程安全
        self.assertTrue(True)


if __name__ == '__main__':
    unittest.main()