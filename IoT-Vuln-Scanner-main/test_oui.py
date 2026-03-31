# 保存为 test_oui.py，放在项目根目录
import sys
sys.path.append('.')

from core.device_identifier import DeviceIdentifier

# 测试识别
identifier = DeviceIdentifier('data/oui.txt')

test_macs = [
    '64:64:4a:29:be:fc',  # 应该是 Xiaomi
    'c0:35:32:3f:e8:c3',  # 应该是 Intel
    '36:2b:cc:0b:36:2a',  # 新出现的设备
]

for mac in test_macs:
    prefix = mac.replace(':', '').upper()[:6]
    vendor = identifier.identify(mac)
    print(f"MAC: {mac}")
    print(f"  前缀: {prefix}")
    print(f"  识别结果: {vendor}")
    print()

# 检查 OUI 数据加载数量
print(f"OUI 数据库条目数: {len(identifier.oui_data)}")
print(f"前5条: {list(identifier.oui_data.items())[:5]}")