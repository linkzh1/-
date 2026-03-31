# scripts\start.py
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
主启动脚本 - IoT Vulnerability Scanner
支持Web UI、API、CLI三种模式，以及统一启动模式
"""
import sys
import os
import argparse
import logging
import signal
import subprocess
import time
import threading
from pathlib import Path

# Windows编码修复：强制UTF-8
if sys.platform == 'win32':
    import codecs

    sys.stdout = codecs.getwriter('utf-8')(sys.stdout.buffer)
    sys.stderr = codecs.getwriter('utf-8')(sys.stderr.buffer)
    os.environ['PYTHONIOENCODING'] = 'utf-8'

# 添加项目根目录到路径
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


def ensure_directories():
    """确保必要目录存在（必须在logging配置前调用）"""
    dirs = ['data', 'config', 'logs', 'backups', 'reports']
    for d in dirs:
        os.makedirs(d, exist_ok=True)


# 先创建目录，避免FileHandler报错
ensure_directories()

# 配置日志
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler('logs/scanner.log', mode='a', encoding='utf-8')
    ]
)
logger = logging.getLogger(__name__)

# 全局变量用于进程管理
processes = []


def check_root():
    """检查root权限（Windows跳过）"""
    if os.name == 'nt':  # Windows
        import ctypes
        try:
            if not ctypes.windll.shell32.IsUserAnAdmin():
                logger.warning("[WARN] 未以管理员身份运行，某些功能可能受限")
        except Exception:
            pass
    else:  # Linux/macOS
        if os.geteuid() != 0:
            logger.warning("[WARN] 未以root运行，ARP扫描等功能可能受限")


def start_flask_service(port=5000, debug=False):
    """启动Flask Web界面（非阻塞版本）"""
    try:
        from ui import create_app
        app = create_app()
        logger.info(f"[Flask] 服务启动于 http://0.0.0.0:{port}")

        if debug:
            routes = [str(rule) for rule in app.url_map.iter_rules()
                      if not str(rule).startswith('/static')]
            logger.debug(f"注册的路由: {routes}")

        app.run(host='0.0.0.0', port=port, debug=debug, threaded=True, use_reloader=False)
    except ImportError as e:
        logger.error(f"导入失败: {e}")
        raise


def start_streamlit_service(port=8501):
    """启动Streamlit前端服务"""
    base_dir = Path(__file__).parent.parent.absolute()

    # 关键修改：使用 app.py 作为入口，而不是 1_Overview.py
    entry_file = base_dir / 'ui' / 'app.py'

    if not entry_file.exists():
        logger.error(f"[Streamlit] 入口文件不存在: {entry_file}")
        return

    logger.info(f"[Streamlit] 服务启动于 http://localhost:{port}")

    cmd = [
        sys.executable, '-m', 'streamlit', 'run',
        str(entry_file),
        '--server.port', str(port),
        '--server.headless', 'true',
        '--server.enableCORS', 'false',
        '--server.enableXsrfProtection', 'false',
        '--browser.gatherUsageStats', 'false'
    ]

    try:
        process = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            bufsize=1,
            universal_newlines=True,
            encoding='utf-8',
            errors='ignore'
        )
        processes.append(process)

        # 实时输出Streamlit日志
        for line in process.stdout:
            if line.strip():
                logger.info(f"[Streamlit] {line.strip()}")

    except Exception as e:
        logger.error(f"[Streamlit] 启动失败: {e}")


def start_web_with_streamlit(flask_port=5000, streamlit_port=8501, debug=False):
    """同时启动Flask和Streamlit"""
    logger.info("=" * 50)
    logger.info("IoT Vulnerability Scanner 双模式启动")
    logger.info("=" * 50)
    logger.info(f"Flask API:    http://localhost:{flask_port}")
    logger.info(f"Streamlit UI: http://localhost:{streamlit_port}")
    logger.info("=" * 50)

    # 启动Flask（在新线程中，因为app.run是阻塞的）
    flask_thread = threading.Thread(
        target=start_flask_service,
        args=(flask_port, debug),
        daemon=True,
        name="FlaskThread"
    )
    flask_thread.start()

    # 等待Flask初始化
    time.sleep(2)

    # 启动Streamlit（在新线程中）
    streamlit_thread = threading.Thread(
        target=start_streamlit_service,
        args=(streamlit_port,),
        daemon=True,
        name="StreamlitThread"
    )
    streamlit_thread.start()

    # 等待Streamlit初始化
    time.sleep(3)

    logger.info("[OK] 双服务启动完成！")
    logger.info("     Flask API: http://localhost:%d" % flask_port)
    logger.info("     Streamlit: http://localhost:%d" % streamlit_port)
    logger.info("[INFO] 按 Ctrl+C 停止所有服务...")

    # 主线程保持运行，监控子线程
    try:
        while True:
            # 检查线程是否还活着
            if not flask_thread.is_alive():
                logger.error("[ERROR] Flask服务异常退出")
                break
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[INFO] 收到停止信号...")
    finally:
        cleanup_processes()


def cleanup_processes():
    """清理所有子进程"""
    logger.info("[INFO] 正在清理进程...")
    for p in processes:
        if p and p.poll() is None:
            p.terminate()
            try:
                p.wait(timeout=5)
            except subprocess.TimeoutExpired:
                p.kill()
    logger.info("[OK] 已停止所有服务")


def start_api_server(port=8000):
    """启动FastAPI服务"""
    try:
        from api.main import start_api
        logger.info(f"启动API服务: http://0.0.0.0:{port}")
        start_api(host='0.0.0.0', port=port)
    except ImportError:
        logger.warning("API模块未安装，跳过API服务")
        pass


def start_cli_scan(target):
    """命令行扫描模式"""
    from core.network.arp_scanner import ARPScanner
    from core.vulnerability.scanner.engine import ScanEngine
    from core.storage.database import Database

    logger.info(f"开始扫描目标: {target}")

    # 网络扫描
    scanner = ARPScanner(target)
    devices = scanner.scan()
    logger.info(f"发现 {len(devices)} 个设备")

    # 漏洞扫描
    engine = ScanEngine()
    db = Database()

    for device in devices:
        logger.info(f"扫描设备: {device.ip}")
        result = engine.scan_device(device.ip)

        # 保存结果
        db.add_device({
            'ip': device.ip,
            'mac': device.mac,
            'vendor': device.vendor,
            'status': 'online',
            'open_ports': result.get('open_ports', []),
            'risk_score': len(result.get('vulnerabilities', [])) * 10
        })

        for vuln in result.get('vulnerabilities', []):
            db.add_vulnerability(device.ip, vuln)
            logger.warning(f"发现漏洞: {vuln.get('cve_id')} - {vuln.get('title')}")

    logger.info("扫描完成")


def signal_handler(sig, frame):
    """优雅退出"""
    logger.info("收到退出信号，正在清理...")
    cleanup_processes()
    sys.exit(0)


def main():
    parser = argparse.ArgumentParser(
        description='IoT Vulnerability Scanner - 智能家居物联网设备漏洞扫描工具',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
示例:
  %(prog)s --mode web                    # 仅启动Flask Web界面
  %(prog)s --mode web --with-streamlit   # 同时启动Flask+Streamlit（推荐）
  %(prog)s --mode api --port 8080        # 仅启动API服务
  %(prog)s --mode cli --target 192.168.1.0/24  # 命令行扫描模式
        """
    )
    parser.add_argument(
        '--mode',
        choices=['web', 'api', 'cli'],
        default='web',
        help='运行模式: web(Web界面), api(API服务), cli(命令行)'
    )
    parser.add_argument(
        '--with-streamlit',
        action='store_true',
        help='Web模式下同时启动Streamlit前端（默认端口8501）'
    )
    parser.add_argument(
        '--streamlit-port',
        type=int,
        default=8501,
        help='Streamlit服务端口（默认8501）'
    )
    parser.add_argument(
        '--target',
        help='CLI模式下的扫描目标(如192.168.1.0/24)'
    )
    parser.add_argument(
        '--port',
        type=int,
        help='服务端口(Flask默认5000，API默认8000)'
    )
    parser.add_argument(
        '--debug',
        action='store_true',
        help='调试模式'
    )

    args = parser.parse_args()

    # 设置信号处理
    signal.signal(signal.SIGINT, signal_handler)
    if hasattr(signal, 'SIGTERM'):
        signal.signal(signal.SIGTERM, signal_handler)

    # 初始化
    check_root()

    try:
        if args.mode == 'web':
            if args.with_streamlit:
                # 同时启动Flask和Streamlit
                flask_port = args.port or 5000
                start_web_with_streamlit(flask_port, args.streamlit_port, args.debug)
            else:
                # 仅启动Flask（原有行为）
                port = args.port or 5000
                logger.info(f"启动Web界面: http://0.0.0.0:{port}")
                logger.info("提示: 使用 --with-streamlit 可同时启动可视化界面")
                start_flask_service(port, args.debug)

        elif args.mode == 'api':
            port = args.port or 8000
            start_api_server(port)

        elif args.mode == 'cli':
            if not args.target:
                print("[ERROR] CLI模式需要指定--target参数")
                sys.exit(1)
            start_cli_scan(args.target)

    except Exception as e:
        logger.error(f"启动失败: {e}", exc_info=True)
        sys.exit(1)


if __name__ == '__main__':
    main()