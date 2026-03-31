# api/routes.py (FastAPI)
from fastapi import FastAPI, Depends
from core.vuln_scanner.engine import ScanEngine

app = FastAPI(title="IoT Scanner API")

@app.post("/scan/{ip}")
async def scan_device(ip: str, engine: ScanEngine = Depends()):
    result = engine.scan_device(ip)
    return {"status": "completed", "vulnerabilities_found": len(result['vulns'])}

@app.get("/devices")
async def list_devices():
    db = Database('data/devices.db')
    return db.get_all_devices()