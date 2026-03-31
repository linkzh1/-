# core/utils/logger.py
import logging
import os
from datetime import datetime


def setup_logger(name: str) -> logging.Logger:
    """配置双通道日志：控制台 + 文件"""
    logger = logging.getLogger(name)
    logger.setLevel(logging.DEBUG)

    # 确保目录存在
    os.makedirs('logs', exist_ok=True)

    # 文件处理器（按日期轮转）
    log_file = f"logs/scanner_{datetime.now().strftime('%Y%m%d')}.log"
    file_handler = logging.FileHandler(log_file, encoding='utf-8')
    file_handler.setLevel(logging.DEBUG)

    # 控制台处理器
    console_handler = logging.StreamHandler()
    console_handler.setLevel(logging.INFO)

    # 格式：时间 | 级别 | 模块 | 消息
    formatter = logging.Formatter(
        '%(asctime)s | %(levelname)-8s | %(name)s | %(message)s',
        datefmt='%Y-%m-%d %H:%M:%S'
    )
    file_handler.setFormatter(formatter)
    console_handler.setFormatter(formatter)

    logger.addHandler(file_handler)
    logger.addHandler(console_handler)

    return logger

# 使用示例（在原有代码中替换）
# from core.utils.logger import setup_logger
# logger = setup_logger(__name__)
# logger.info(f"发现设备: {device['ip']}")
# logger.error(f"扫描失败: {e}", exc_info=True)