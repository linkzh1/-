# test_camera.py
"""
模拟脆弱 ONVIF 摄像头 - 无需 Docker
运行: python test_camera.py
"""

from http.server import HTTPServer, BaseHTTPRequestHandler


class ONVIFCameraHandler(BaseHTTPRequestHandler):
    """模拟带漏洞的 ONVIF 摄像头"""

    def log_message(self, format, *args):
        print(f"[摄像头] {self.client_address[0]} - {format % args}")

    def do_POST(self):
        """处理 ONVIF SOAP 请求"""
        if '/onvif' in self.path or 'device_service' in self.path:
            content_length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(content_length)

            print(f"\n[收到 ONVIF 请求] {self.path}")
            print(f"[请求内容] {body.decode('utf-8', errors='ignore')[:300]}")

            # 模拟未授权访问 - 直接返回设备信息
            response = b'''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://www.w3.org/2003/05/soap-envelope"
                   xmlns:tds="http://www.onvif.org/ver10/device/wsdl">
    <SOAP-ENV:Body>
        <tds:GetDeviceInformationResponse>
            <tds:Manufacturer>Hikvision</tds:Manufacturer>
            <tds:Model>DS-2CD2143G0-I</tds:Model>
            <tds:FirmwareVersion>V5.5.0 build 180808</tds:FirmwareVersion>
            <tds:SerialNumber>DS-TEST123456789</tds:SerialNumber>
            <tds:HardwareId>88</tds:HardwareId>
        </tds:GetDeviceInformationResponse>
    </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

            self.send_response(200)
            self.send_header('Content-Type', 'application/soap+xml; charset=utf-8')
            self.send_header('Content-Length', len(response))
            self.end_headers()
            self.wfile.write(response)

            print("[+] 返回设备信息（漏洞：无需认证）")

        else:
            self.send_error(404)

    def do_GET(self):
        """模拟 Web 管理界面"""
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.end_headers()

        # 使用普通字符串，最后编码成 bytes
        html = '''
        <html>
        <head>
            <title>Hikvision IP Camera</title>
            <style>
                body { font-family: Arial; margin: 50px; background: #f0f0f0; }
                .login-box { background: white; padding: 30px; border-radius: 10px; width: 300px; margin: 0 auto; }
                input { width: 100%; padding: 10px; margin: 5px 0; }
                button { width: 100%; padding: 10px; background: #007bff; color: white; border: none; }
            </style>
        </head>
        <body>
            <div class="login-box">
                <h2>Camera Login</h2>
                <form action="/login" method="post">
                    <input type="text" name="username" value="admin" placeholder="Username"><br>
                    <input type="password" name="password" value="admin" placeholder="Password"><br>
                    <button type="submit">Login</button>
                </form>
                <p style="color: red; font-size: 12px;">Default: admin/admin</p>
            </div>
        </body>
        </html>
        '''
        # 关键修复：字符串编码成 bytes
        self.wfile.write(html.encode('utf-8'))


def start_camera():
    server = HTTPServer(('0.0.0.0', 8000), ONVIFCameraHandler)
    print("=" * 50)
    print("[+] Vulnerable Camera Started!")
    print("[+] URL: http://127.0.0.1:8000")
    print("[+] ONVIF: http://127.0.0.1:8000/onvif/device_service")
    print("[+] Vuln: ONVIF No Auth + Default Password")
    print("=" * 50)
    print("Press Ctrl+C to stop...\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Camera stopped")


if __name__ == '__main__':
    start_camera()