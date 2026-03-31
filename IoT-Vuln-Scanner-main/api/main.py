# api/main.py
"""
FastAPI REST API接口
提供HTTP API供外部调用
"""
from fastapi import FastAPI, HTTPException, BackgroundTasks, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional, Dict
import uvicorn
import logging

from core.network.arp_scanner import ARPScanner
from core.vulnerability.scanner.engine import ScanEngine
from core.storage.database import Database

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(
    title="IoT Vulnerability Scanner API",
    description="IoT设备安全检测REST API",
    version="2.0.0"
)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


# 数据模型
class ScanRequest(BaseModel):
    target: str  # IP或网段
    scan_type: str = "full"  # quick, full, custom
    ports: Optional[List[int]] = None


class DeviceResponse(BaseModel):
    ip: str
    mac: Optional[str]
    vendor: Optional[str]
    status: str
    open_ports: List[int]
    risk_score: float


@app.get("/")
async def root():
    return {"message": "IoT Scanner API v2.0", "status": "running"}


@app.post("/scan", response_model=Dict)
async def start_scan(request: ScanRequest, background_tasks: BackgroundTasks):
    """启动扫描任务"""
    try:
        if '/' in request.target:  # 网段扫描
            scanner = ARPScanner(request.target)
            devices = scanner.scan()

            # 后台执行深度扫描
            background_tasks.add_task(deep_scan_devices, devices)

            return {
                "status": "accepted",
                "devices_found": len(devices),
                "message": f"发现 {len(devices)} 个设备，后台扫描中"
            }
        else:  # 单IP扫描
            engine = ScanEngine()
            result = engine.scan_device(request.target)
            return {
                "status": "completed",
                "result": result
            }

    except Exception as e:
        logger.error(f"扫描失败: {e}")
        raise HTTPException(status_code=500, detail=str(e))


def deep_scan_devices(devices):
    """后台深度扫描"""
    engine = ScanEngine()
    db = Database()

    for device in devices:
        try:
            result = engine.scan_device(device.ip)

            # 保存到数据库
            device_data = {
                'ip': device.ip,
                'mac': device.mac,
                'vendor': device.vendor,
                'status': 'online',
                'open_ports': result.get('open_ports', []),
                'risk_score': len(result.get('vulnerabilities', [])) * 10
            }
            db.add_device(device_data)

            # 保存漏洞
            for vuln in result.get('vulnerabilities', []):
                db.add_vulnerability(device.ip, vuln)

        except Exception as e:
            logger.error(f"扫描设备 {device.ip} 失败: {e}")


@app.get("/devices", response_model=List[DeviceResponse])
async def list_devices(status: Optional[str] = None):
    """获取设备列表"""
    db = Database()
    devices = db.get_all_devices()

    if status:
        devices = [d for d in devices if d.get('status') == status]

    return devices


@app.get("/devices/{ip}/vulnerabilities")
async def get_device_vulnerabilities(ip: str):
    """获取设备漏洞"""
    db = Database()
    vulns = db.get_device_vulnerabilities(ip)
    return {"ip": ip, "vulnerabilities": vulns, "count": len(vulns)}


@app.get("/statistics")
async def get_statistics():
    """获取全局统计"""
    db = Database()
    stats = {
        "total_devices": len(db.get_all_devices()),
        "vulnerable_devices": len(db.get_vulnerable_devices()),
        "device_types": db.get_device_types_stats(),
        "recent_scans": db.get_today_scans()
    }
    return stats


def start_api(host="0.0.0.0", port=8000):
    """启动API服务器"""
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    start_api()