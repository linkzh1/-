# ui\pages\2_Device_Details.py
import streamlit as st
import sys
import os
import json
from datetime import datetime, timedelta

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.storage.database import Database
from core.vulnerability.scanner.engine import ScanEngine
from ui.common import (
    show_privacy_banner,
    mask_device_data,
    load_privacy_config,
    get_severity_color,
    cache_with_ttl
)
import pandas as pd

st.set_page_config(
    page_title="设备详情",
    page_icon="📱",
    layout="wide",
    initial_sidebar_state="expanded"
)

# 隐藏默认的英文侧边栏导航
st.markdown("""
<style>
    [data-testid="stSidebarNav"] {
        display: none !important;
    }
</style>
""", unsafe_allow_html=True)

# 侧边栏中文导航
with st.sidebar:
    st.markdown("### 🧭 功能导航")
    st.page_link("app.py", label="🏠 首页", icon="🏠")
    st.page_link("pages/1_Overview.py", label="📊 网络概览", icon="📊")
    st.page_link("pages/2_Device_Details.py", label="💻 设备详情", icon="💻", disabled=True)
    st.page_link("pages/3_Settings.py", label="⚙️ 系统设置", icon="⚙️")
    st.page_link("pages/4_Survey.py", label="📝 问卷", icon="📝")
    st.divider()
    st.caption("🔄 当前页面：设备详情")

show_privacy_banner()
st.title("📱 设备安全详情")

# 初始化数据库 - 确保与Overview使用相同路径
try:
    current_file = os.path.abspath(__file__)
    project_root = os.path.dirname(os.path.dirname(os.path.dirname(current_file)))
    db_path = os.path.join(project_root, 'data', 'devices.db')

    st.sidebar.caption(f"📁 DB路径: {db_path[-30:]}")
    os.makedirs(os.path.dirname(db_path), exist_ok=True)
    db = Database(db_path)
    privacy_config = load_privacy_config()
except Exception as e:
    st.error(f"初始化失败: {str(e)}")
    st.stop()


@cache_with_ttl(seconds=5)
def get_devices_cached():
    try:
        devices = db.get_all_devices() or []
        st.sidebar.metric("📊 数据库设备数", len(devices))
        return devices
    except Exception as e:
        st.sidebar.error(f"❌ 获取失败: {str(e)}")
        return []


devices = get_devices_cached()

if not devices:
    st.warning("⚠️ 未发现设备，请先运行网络扫描或在Overview页面添加测试数据")

    col1, col2 = st.columns(2)
    with col1:
        if st.button("🔄 刷新数据"):
            st.rerun()
    with col2:
        if st.button("➕ 添加测试设备"):
            try:
                test_device = {
                    'ip': '192.168.99.101',
                    'mac': 'AA:BB:CC:DD:EE:01',
                    'vendor': 'Test-Device',
                    'device_type': '路由器',
                    'status': 'online',
                    'open_ports': [{'port': 80, 'service': 'http'}],
                    'services': {},
                    'risk_score': 6.5,
                    'first_seen': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
                    'last_scan': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
                }
                result = db.add_device(test_device)
                if result:
                    st.success("✅ 已添加")
                    st.rerun()
                else:
                    st.error("❌ 添加失败")
            except Exception as e:
                st.error(f"添加失败: {e}")
    st.stop()

# 设备选择器
st.subheader("选择目标设备")

# 构建设备选项
device_options = {}
duplicate_check = {}

for d in devices:
    status_icon = "🟢" if d.get('status') == 'online' else "🔴"
    risk_score = d.get('risk_score', 0)
    risk_badge = ""
    if risk_score >= 7:
        risk_badge = " 🔴高危"
    elif risk_score >= 4:
        risk_badge = " 🟡中危"

    # 新设备检查
    is_new = False
    if d.get('first_seen'):
        try:
            first_seen = datetime.strptime(d['first_seen'], '%Y-%m-%d %H:%M:%S')
            if datetime.now() - first_seen < timedelta(hours=24):
                is_new = True
                risk_badge += " ✨新"
        except:
            pass

    # 生成显示名称
    display_name = f"{status_icon} {d.get('ip', 'N/A')} - {d.get('vendor', 'Unknown')} ({d.get('mac', 'N/A')[:17]}){risk_badge}"

    # 处理重复名称
    if display_name in duplicate_check:
        count = duplicate_check[display_name]
        duplicate_check[display_name] = count + 1
        display_name = f"{display_name} #{count + 1}"
    else:
        duplicate_check[display_name] = 1

    device_options[display_name] = d

# 筛选功能
filter_col1, filter_col2 = st.columns([3, 1])
with filter_col2:
    filter_status = st.selectbox("筛选", ["全部", "仅在线", "高风险", "新设备"], key="filter_select")

filtered_options = {}
for name, device in device_options.items():
    if filter_status == "仅在线" and "🔴" in name:
        continue
    if filter_status == "高风险" and "🔴高危" not in name:
        continue
    if filter_status == "新设备" and "✨新" not in name:
        continue
    filtered_options[name] = device

if not filtered_options:
    st.warning("没有符合条件的设备")
    st.stop()

# 修复：确保下拉框可以正常显示和选择所有设备
st.caption(f"📱 找到 {len(filtered_options)} 个设备")

# 使用更宽的布局确保下拉框正常显示
col_select, _ = st.columns([3, 1])
with col_select:
    # 关键修复：添加 key 参数避免缓存问题，使用 list() 确保是列表
    option_list = list(filtered_options.keys())

    selected_name = st.selectbox(
        label="选择设备",  # 添加标签便于识别
        options=option_list,
        index=0,  # 默认选择第一个
        label_visibility="collapsed",
        key="device_selector_main_v2"  # 关键：唯一key避免冲突
    )

# 验证选择是否有效
if selected_name not in filtered_options:
    st.error("选择错误，请重新选择")
    st.stop()

selected_device = filtered_options[selected_name]

# 🔴 关键修复：保存原始IP地址用于数据库查询，避免脱敏后查询失败
original_ip = selected_device.get('ip')
st.caption(f"当前选中: {selected_name} (原始IP: {original_ip})")

# 脱敏处理 - 使用副本避免修改原始数据
display_device, is_masked = mask_device_data(selected_device.copy())

st.divider()

# 设备信息三栏布局
col1, col2, col3 = st.columns([1.2, 1.5, 1.3])

with col1:
    st.subheader("📋 设备画像")
    status_color = "normal" if selected_device.get('status') == 'online' else "off"
    st.metric("连接状态", "🟢 在线" if selected_device.get('status') == 'online' else "🔴 离线",
              delta="实时" if selected_device.get('status') == 'online' else "已断开",
              delta_color=status_color)

    st.write(f"**IP 地址**: `{display_device['ip']}`")
    st.write(f"**MAC 地址**: `{display_device['mac']}`")
    st.write(f"**厂商**: {selected_device.get('vendor', 'Unknown')}")
    st.write(f"**设备类型**: {selected_device.get('device_type', '未识别')}")

    st.caption(f"📅 首次发现: {selected_device.get('first_seen', 'N/A')}")
    st.caption(f"🔄 最后扫描: {selected_device.get('last_scan', 'N/A')}")

    if is_masked:
        with st.expander("🔒 查看脱敏说明"):
            st.caption("IP地址保留了网段信息用于网络管理，隐藏了主机标识。")

with col2:
    st.subheader("🌐 开放服务")
    ports = selected_device.get('open_ports', [])
    if ports:
        ports_data = []
        for p in ports:
            ports_data.append({
                "端口": p.get('port', 'N/A'),
                "协议": p.get('protocol', 'tcp').upper(),
                "服务": p.get('service', 'unknown'),
                "版本": p.get('version', '-') or "-",
                "产品": p.get('product', '-') or "-"
            })
        df_ports = pd.DataFrame(ports_data)
        st.dataframe(df_ports, use_container_width=True, hide_index=True)

        risk_ports = [p for p in ports if p.get('port') in [23, 21, 3389, 445, 135, 139]]
        if risk_ports:
            st.warning(f"⚠️ 发现 {len(risk_ports)} 个潜在高风险端口")
    else:
        st.info("未发现开放端口")

with col3:
    st.subheader("📊 安全评分")
    risk_score = selected_device.get('risk_score', 0)

    if risk_score >= 7:
        bar_color = "linear-gradient(90deg, #ff0000, #ff6600)"
        grade = "🔴 高危"
    elif risk_score >= 4:
        bar_color = "linear-gradient(90deg, #ff9900, #ffcc00)"
        grade = "🟡 中危"
    else:
        bar_color = "linear-gradient(90deg, #00cc66, #00ff99)"
        grade = "🟢 低危"

    st.markdown(f"""
    <div style="text-align: center; margin-bottom: 10px;">
        <span style="font-size: 32px; font-weight: bold;">{risk_score}/10</span>
        <br><span style="font-size: 18px;">{grade}</span>
    </div>
    <div style="height: 20px; background: #e0e0e0; border-radius: 10px; overflow: hidden;">
        <div style="width: {risk_score * 10}%; height: 100%; background: {bar_color};"></div>
    </div>
    """, unsafe_allow_html=True)

    vuln_count = selected_device.get('vulnerability_count', 0)
    st.metric("已知漏洞", vuln_count, delta="需立即处理" if vuln_count > 5 else "可控",
              delta_color="inverse" if vuln_count > 5 else "off")

st.divider()

# 🚨 修复后的漏洞详情部分
st.subheader("🚨 安全漏洞详情")

# 使用原始IP查询数据库，并添加调试信息
vulns = []
query_error = None

try:
    # 🔴 关键：使用原始IP而不是可能脱敏后的IP
    if original_ip and original_ip != 'N/A':
        vulns = db.get_device_vulnerabilities(original_ip)
        if vulns is None:
            vulns = []
    else:
        query_error = "设备IP无效"
except Exception as e:
    query_error = str(e)
    vulns = []

# 如果数据库中没有漏洞记录，但风险评分较高，尝试从设备对象中获取
if not vulns and risk_score > 0:
    # 检查是否有embedded的漏洞数据
    embedded_vulns = selected_device.get('vulnerabilities', [])
    if embedded_vulns:
        vulns = embedded_vulns

# 显示漏洞列表
if vulns:
    severity_filter = st.multiselect(
        "筛选严重程度",
        ["Critical", "High", "Medium", "Low"],
        default=["Critical", "High", "Medium"],
        key="severity_filter"
    )

    filtered_vulns = [v for v in vulns if v.get('severity') in severity_filter]

    if filtered_vulns:
        st.caption(f"共发现 {len(filtered_vulns)} 个符合条件的漏洞 (总计: {len(vulns)})")

        for vuln in filtered_vulns:
            severity = vuln.get('severity', 'Medium')
            color = get_severity_color(severity)
            icon = {'Critical': '🔴', 'High': '🟠', 'Medium': '🟡', 'Low': '🟢'}.get(severity, '⚪')
            cvss = vuln.get('cvss_score', 0)

            with st.expander(f"{icon} {vuln.get('cve_id', 'Unknown')} - {vuln.get('title', '无标题')}"):
                col_v1, col_v2 = st.columns([3, 1])

                with col_v1:
                    st.markdown(f"**严重等级**: <span style='color:{color}; font-weight:bold;'>{severity}</span>",
                                unsafe_allow_html=True)
                    st.write(f"**描述**: {vuln.get('description', '暂无描述')}")

                    # 修复：把内层expander改为直接显示，避免嵌套
                    st.markdown("**📖 修复方案:**")
                    st.info(vuln.get('solution', '请联系厂商获取安全补丁'))

                with col_v2:
                    if cvss:
                        st.write("**CVSS 评分**")
                        st.markdown(
                            f"<div style='text-align: center; font-size: 24px; font-weight: bold; color: {color};'>{cvss}</div>",
                            unsafe_allow_html=True)
                        st.progress(cvss / 10, text=f"{cvss}/10")

                    if vuln.get('poc_available'):
                        st.error("⚠️ POC可利用")
    else:
        st.info(f"没有符合筛选条件的漏洞 (总计 {len(vulns)} 个漏洞)")
else:
    # 根据风险评分显示不同的提示
    if risk_score >= 4:
        st.warning(f"⚠️ 风险评分为 {risk_score}，但未在数据库中找到漏洞记录。可能原因：\n"
                   f"1. 漏洞数据尚未同步到数据库\n"
                   f"2. 风险来自开放端口或配置问题而非已知CVE\n"
                   f"3. 数据库查询失败: {query_error if query_error else '无错误信息'}")
    else:
        st.success("✅ 未发现已知安全漏洞")

st.divider()

# 操作区域（3列，已删除生成报告）
st.subheader("🛠️ 操作")

col_op1, col_op2, col_op3 = st.columns(3)

with col_op1:
    if st.button("🔄 深度扫描", type="primary", use_container_width=True):
        with st.spinner("🔍 正在执行深度安全扫描..."):
            try:
                # 终端输出开始信息
                print("\n" + "=" * 50)
                print(f"🔍 [深度扫描] 开始扫描设备: {original_ip}")
                print(f"   设备类型: {selected_device.get('device_type', 'Unknown')}")
                print(f"   厂商: {selected_device.get('vendor', 'Unknown')}")
                print("=" * 50)

                engine = ScanEngine()
                device_info = {
                    'ip': original_ip,
                    'mac': selected_device.get('mac'),
                    'device_type': selected_device.get('device_type'),
                    'open_ports': selected_device.get('open_ports', [])
                }

                print(f"📡 正在连接设备 {original_ip} ...")
                try:
                    result = engine.scan_device(device_info)
                except TypeError:
                    result = engine.scan_device(original_ip)

                vuln_list = result.get('vulnerabilities', [])
                auth_issues = result.get('auth_issues', [])
                protocol_issues = result.get('protocol_issues', [])
                total_issues = len(vuln_list) + len(auth_issues) + len(protocol_issues)

                print(f"✅ 扫描完成！发现 {total_issues} 个安全问题")
                print(f"   - 漏洞: {len(vuln_list)} 个")
                print(f"   - 认证问题: {len(auth_issues)} 个")
                print(f"   - 协议问题: {len(protocol_issues)} 个")
                print("-" * 50)

                # 🆕 关键修复：将发现的漏洞保存到数据库
                saved_count = 0
                if vuln_list:
                    print("\n📋 漏洞详情:")
                    for idx, vuln in enumerate(vuln_list, 1):
                        print(f"  [{idx}] {vuln.get('cve_id', 'UNKNOWN')}: {vuln.get('title', '无标题')[:50]}...")
                        print(f"       严重等级: {vuln.get('severity', 'Unknown')} | CVSS: {vuln.get('cvss_score', 'N/A')}")

                    try:
                        for vuln in vuln_list:
                            vuln_data = {
                                'cve_id': vuln.get('cve_id') or vuln.get('type', 'UNKNOWN'),
                                'title': (vuln.get('title') or vuln.get('description', '无标题'))[:100],
                                'description': vuln.get('description', '暂无描述'),
                                'severity': vuln.get('severity', 'Medium'),
                                'cvss_score': float(vuln.get('cvss_score', 5.0) or 5.0),
                                'solution': vuln.get('solution') or vuln.get('fix', '请联系厂商获取安全补丁'),
                                'poc_available': vuln.get('poc_available', False)
                            }

                            success = db.add_vulnerability(
                                device_ip=original_ip,
                                vuln=vuln_data
                            )
                            if success:
                                saved_count += 1
                                print(f"   ✅ 已保存漏洞: {vuln_data['cve_id']}")

                        if saved_count > 0:
                            st.success(f"✅ 已保存 {saved_count}/{len(vuln_list)} 个漏洞到数据库")
                            print(f"\n💾 成功保存 {saved_count}/{len(vuln_list)} 个漏洞到数据库")
                        else:
                            st.warning("⚠️ 扫描完成但未能保存漏洞数据")
                            print("\n⚠️ 警告: 未能保存漏洞数据")

                    except Exception as save_err:
                        st.error(f"❌ 保存漏洞失败: {str(save_err)}")
                        print(f"\n❌ 保存漏洞失败: {str(save_err)}")

                # 更新设备风险评分
                try:
                    new_risk_score = min(sum({
                                                 'Critical': 10, 'High': 7, 'Medium': 4, 'Low': 1
                                             }.get(v.get('severity', 'Low'), 1) for v in vuln_list), 10)

                    db.update_device_risk(original_ip, new_risk_score, len(vuln_list))
                    st.info(f"📊 设备风险评分已更新为: {new_risk_score}/10")
                    print(f"📊 设备风险评分已更新: {new_risk_score}/10")
                except Exception as update_err:
                    st.warning(f"更新设备风险评分失败: {update_err}")
                    print(f"⚠️ 更新风险评分失败: {update_err}")

                print("=" * 50 + "\n")

                # 显示扫描结果摘要（Web界面）
                if total_issues > 0:
                    st.error(
                        f"🚨 发现 {total_issues} 个安全问题 (漏洞: {len(vuln_list)}, 认证问题: {len(auth_issues)}, 协议问题: {len(protocol_issues)})")

                    if vuln_list:
                        st.write("**🔍 发现的漏洞详情:**")
                        for v in vuln_list[:5]:
                            severity_icon = {"Critical": "🔴", "High": "🟠", "Medium": "🟡", "Low": "🟢"}.get(
                                v.get('severity'), "⚪")
                            st.write(f"{severity_icon} **{v.get('cve_id', 'Unknown')}**: {v.get('title', '无标题')}")

                        if len(vuln_list) > 5:
                            st.caption(f"... 还有 {len(vuln_list) - 5} 个漏洞已保存到数据库")
                else:
                    st.success("✅ 扫描完成，未发现安全问题")
                    print("✅ 扫描完成，未发现安全问题\n")

                if st.button("🔄 刷新页面查看更新", key="refresh_after_scan"):
                    st.rerun()

            except Exception as e:
                st.error(f"扫描失败: {str(e)}")
                print(f"\n❌ 扫描失败: {str(e)}")
                import traceback

                st.code(traceback.format_exc(), language="python")

with col_op2:
    if st.button("🔇 忽略设备", use_container_width=True):
        st.warning("🚧 功能开发中：将此设备加入白名单", icon="⚠️")

with col_op3:
    if st.button("🗑️ 删除记录", type="secondary", use_container_width=True):
        st.error("⚠️ 确认删除？")
        col_confirm, col_cancel = st.columns(2)
        with col_confirm:
            if st.button("确认删除", type="primary", key="confirm_delete"):
                try:
                    # 尝试删除设备
                    if hasattr(db, 'delete_device'):
                        db.delete_device(original_ip)
                        st.success("✅ 设备已删除")
                        st.rerun()
                    else:
                        st.error("演示模式：无删除权限")
                except Exception as del_err:
                    st.error(f"删除失败: {del_err}")

st.divider()
st.info("💡 提示：使用 **左侧侧边栏** 可切换到其他页面")