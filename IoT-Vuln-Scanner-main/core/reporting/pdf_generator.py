@device_bp.route('/api/report/pdf/<mac>')
def generate_pdf_report(mac):
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.units import cm
        from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
        from reportlab.pdfbase import pdfmetrics
        from reportlab.pdfbase.ttfonts import TTFont

        conn = create_connection('data/devices.db')
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM devices WHERE mac=?", (mac,))
        device_row = cursor.fetchone()

        if not device_row:
            conn.close()
            return jsonify({'error': '设备不存在'}), 404

        device_data = {
            'ip': device_row[1], 'mac': device_row[2],
            'vendor': device_row[3] or 'Unknown',
            'device_type': device_row[4] or 'Unknown'
        }

        # ✅ 修改后的查询：按漏洞类型去重，保留最新记录，按严重程度排序
        cursor.execute('''
            SELECT vuln_type, severity, description, fix_suggestion, MAX(scan_time) as scan_time 
            FROM active_vuln_results 
            WHERE device_mac=? OR device_ip=?
            GROUP BY vuln_type
            ORDER BY 
                CASE severity 
                    WHEN 'Critical' THEN 1 
                    WHEN 'CRITICAL' THEN 1
                    WHEN 'HIGH' THEN 2 
                    WHEN 'High' THEN 2 
                    WHEN 'MEDIUM' THEN 3 
                    WHEN 'Medium' THEN 3 
                    WHEN 'LOW' THEN 4 
                    WHEN 'Low' THEN 4 
                    ELSE 5 
                END,
                scan_time DESC
        ''', (mac, device_data['ip']))

        vulnerabilities = []
        for row in cursor.fetchall():
            vulnerabilities.append({
                'type': row[0], 'severity': row[1],
                'description': row[2] or '暂无描述',
                'fix': row[3] or '建议联系厂商更新固件',
                'scan_time': row[4] or 'N/A'
            })
        conn.close()

        risk_score = 0
        if vulnerabilities:
            weights = {'Critical': 10, 'HIGH': 7, 'High': 7, 'MEDIUM': 4, 'Medium': 4, 'LOW': 1, 'Low': 1}
            risk_score = min(sum(weights.get(v.get('severity', 'Low'), 1) for v in vulnerabilities), 10)

        buffer = io.BytesIO()
        doc = SimpleDocTemplate(buffer, pagesize=A4, rightMargin=72, leftMargin=72, topMargin=72, bottomMargin=18)
        elements = []

        chinese_font = 'Helvetica'
        font_paths = [
            "C:/Windows/Fonts/simhei.ttf",
            "C:/Windows/Fonts/simsun.ttc",
            "/usr/share/fonts/truetype/wqy/wqy-zenhei.ttc",
            "/System/Library/Fonts/PingFang.ttc"
        ]
        for font_path in font_paths:
            if os.path.exists(font_path):
                try:
                    font_name = "ChineseFont"
                    pdfmetrics.registerFont(TTFont(font_name, font_path))
                    chinese_font = font_name
                    break
                except:
                    continue

        styles = getSampleStyleSheet()
        title_style = ParagraphStyle('Title', parent=styles['Heading1'], fontName=chinese_font, fontSize=24,
                                     alignment=1)
        normal_style = ParagraphStyle('Normal', parent=styles['BodyText'], fontName=chinese_font, fontSize=10)

        elements.append(Paragraph("IoT 设备安全评估报告", title_style))
        elements.append(Spacer(1, 0.5 * cm))
        elements.append(Paragraph(f"设备: {device_data['ip']} | {device_data['mac']}", normal_style))
        elements.append(Paragraph(f"风险评分: {risk_score}/10", normal_style))
        elements.append(Spacer(1, 1 * cm))

        if vulnerabilities:
            data = [['漏洞类型', '严重程度', '修复建议']]
            for v in vulnerabilities[:20]:
                data.append([v['type'][:30], v['severity'], v['fix'][:40]])

            table = Table(data, colWidths=[6 * cm, 3 * cm, 6 * cm])
            table.setStyle(TableStyle([
                ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
                ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
                ('FONTNAME', (0, 0), (-1, -1), chinese_font),
                ('GRID', (0, 0), (-1, -1), 0.5, colors.black)
            ]))
            elements.append(table)

        doc.build(elements)
        buffer.seek(0)
        return send_file(buffer, mimetype='application/pdf',
                         as_attachment=True,
                         download_name=f"Report_{mac.replace(':', '-')}_{datetime.now().strftime('%Y%m%d')}.pdf")
    except Exception as e:
        return jsonify({'error': str(e)}), 500