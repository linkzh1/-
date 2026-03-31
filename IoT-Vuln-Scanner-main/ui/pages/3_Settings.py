# ui\pages\3_Settings.py
import streamlit as st
import sys
import os
import json
import shutil
from datetime import datetime, timedelta
from io import BytesIO

sys.path.append(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))))

from core.storage.database import Database
from ui.common import (
    load_privacy_config,
    check_consent_status,
    save_consent
)

st.set_page_config(
    page_title="系统设置",
    page_icon="⚙️",
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
    st.page_link("pages/2_Device_Details.py", label="💻 设备详情", icon="💻")
    st.page_link("pages/3_Settings.py", label="⚙️ 系统设置", icon="⚙️", disabled=True)
    st.page_link("pages/4_Survey.py", label="📝 问卷", icon="📝")
    st.divider()
    st.caption("🔄 当前页面：系统设置")

st.title("⚙️ 系统设置与配置中心")


def init_database():
    """确保数据库文件和表结构存在，避免 NoneType 错误"""
    try:
        os.makedirs('data', exist_ok=True)
        db = Database('data/devices.db')
        return True
    except Exception as e:
        st.error(f"数据库初始化失败: {e}")
        return False


db_initialized = init_database()

privacy_cfg = load_privacy_config()
if privacy_cfg.get('enable_anonymization'):
    st.info("🔒 当前隐私保护已开启", icon="🛡️")
else:
    st.warning("⚠️ 当前隐私保护已关闭", icon="👁️")

CONFIG_DIR = 'config'
SCAN_CONFIG_FILE = os.path.join(CONFIG_DIR, 'scan_config.json')
PRIVACY_CONFIG_FILE = os.path.join(CONFIG_DIR, 'privacy_config.json')

os.makedirs(CONFIG_DIR, exist_ok=True)
os.makedirs('data', exist_ok=True)


def save_config(file_path, config):
    with open(file_path, 'w', encoding='utf-8') as f:
        json.dump(config, f, indent=4, ensure_ascii=False)


default_scan = {
    "scan_timeout": 30, "max_threads": 10, "port_range": "1-1000",
    "enable_poc": True, "scan_mode": "standard"
}

scan_config = default_scan.copy()
if os.path.exists(SCAN_CONFIG_FILE):
    try:
        with open(SCAN_CONFIG_FILE, 'r') as f:
            scan_config = {**default_scan, **json.load(f)}
    except:
        pass

privacy_config = privacy_cfg

with st.sidebar:
    st.subheader("📊 系统状态")
    try:
        db = Database('data/devices.db')
        try:
            devices = db.get_all_devices()
            device_count = len(devices) if devices else 0
        except:
            device_count = 0
        st.metric("设备记录数", device_count)

        if os.path.exists('data/devices.db'):
            db_size = os.path.getsize('data/devices.db') / (1024 * 1024)
            st.metric("数据库大小", f"{db_size:.2f} MB")

        try:
            total, used, free = shutil.disk_usage("/")
            st.progress(free / total, text=f"磁盘剩余: {free // (2 ** 30)}GB")
        except:
            st.caption("磁盘信息获取失败")

    except Exception as e:
        st.error("数据库连接失败")
        st.caption("请检查 data/devices.db 是否存在")

st.divider()

col_left, col_right = st.columns(2)

with col_left:
    st.subheader("🔍 扫描引擎配置")

    scan_mode_list = ["custom", "quick", "standard", "comprehensive"]
    current_mode = scan_config.get("scan_mode", "standard")

    try:
        current_index = scan_mode_list.index(current_mode)
    except ValueError:
        current_index = 2

    scan_preset = st.selectbox(
        "扫描模式预设",
        ["自定义", "快速扫描", "标准扫描", "全面扫描"],
        index=current_index
    )

    preset_params = {
        "快速扫描": {"timeout": 10, "threads": 20, "ports": "22,80,443,8080"},
        "标准扫描": {"timeout": 30, "threads": 10, "ports": "1-1000"},
        "全面扫描": {"timeout": 120, "threads": 30, "ports": "1-65535"}
    }

    if scan_preset != "自定义":
        p = preset_params[scan_preset]
        scan_config["scan_timeout"] = p["timeout"]
        scan_config["max_threads"] = p["threads"]
        scan_config["port_range"] = p["ports"]

    with st.form("scan_settings"):
        col1, col2 = st.columns(2)
        with col1:
            scan_timeout = st.number_input("⏱️ 扫描超时(秒)", 1, 300,
                                           scan_config["scan_timeout"])
            max_threads = st.slider("🧵 并发线程数", 1, 50,
                                    scan_config["max_threads"])
        with col2:
            port_range = st.text_input("🚪 扫描端口范围",
                                       scan_config["port_range"])
            enable_poc = st.checkbox("✅ 启用POC验证",
                                     scan_config["enable_poc"])

        with st.expander("🔧 高级选项"):
            enable_cve_check = st.checkbox("查询在线CVE数据库", True)
            aggressive_scan = st.checkbox("激进扫描模式", False)

        if st.form_submit_button("💾 保存扫描设置", use_container_width=True):
            new_config = {
                "scan_timeout": scan_timeout, "max_threads": max_threads,
                "port_range": port_range, "enable_poc": enable_poc,
                "scan_mode": scan_preset.lower().replace("扫描", "") if scan_preset != "自定义" else "custom",
                "enable_cve_check": enable_cve_check, "aggressive_scan": aggressive_scan
            }
            save_config(SCAN_CONFIG_FILE, new_config)
            st.session_state['scan_config'] = new_config
            st.success("✅ 扫描设置已保存！")

with col_right:
    st.subheader("🔒 隐私与合规设置")

    with st.form("privacy_settings"):
        enable_anonymization = st.checkbox(
            "🛡️ 启用数据自动匿名化",
            privacy_config["enable_anonymization"]
        )

        mask_level = st.radio(
            "📵 IP掩码级别",
            ["部分掩码(保留前后段)", "完全掩码(仅保留后8位)"],
            index=0 if privacy_config.get("mask_level") == "partial" else 1
        )

        col_p1, col_p2 = st.columns(2)
        with col_p1:
            retention_days = st.number_input(
                "📅 数据保留天数", 1, 365,
                privacy_config["retention_days"]
            )
        with col_p2:
            auto_cleanup = st.checkbox(
                "🗑️ 自动清理过期数据",
                privacy_config.get("auto_cleanup", False)
            )

        consent_required = st.checkbox(
            "✋ 强制用户同意",
            privacy_config.get("consent_required", True)
        )

        if st.form_submit_button("💾 保存隐私设置", use_container_width=True):
            new_privacy = {
                "enable_anonymization": enable_anonymization,
                "mask_level": "partial" if mask_level.startswith("部分") else "full",
                "retention_days": retention_days,
                "auto_cleanup": auto_cleanup,
                "consent_required": consent_required
            }
            save_config(PRIVACY_CONFIG_FILE, new_privacy)
            st.session_state['privacy_config'] = new_privacy
            st.success("✅ 隐私设置已保存！")
            st.rerun()

    if enable_anonymization:
        st.divider()
        st.caption("👁️ 匿名化效果预览")
        test_ip = "192.168.1.100"
        test_mac = "00:11:22:33:44:55"

        if mask_level.startswith("部分"):
            masked_ip = "192.168.***.100"
            masked_mac = "00:11:22:XX:XX:XX"
        else:
            masked_ip = "***.***.***.100"
            masked_mac = "XX:XX:XX:XX:XX:XX"

        col_prev1, col_prev2 = st.columns(2)
        with col_prev1:
            st.text_input("原始 IP", test_ip, disabled=True)
            st.text_input("脱敏后 IP", masked_ip, disabled=True)
        with col_prev2:
            st.text_input("原始 MAC", test_mac, disabled=True)
            st.text_input("脱敏后 MAC", masked_mac, disabled=True)

st.divider()

st.subheader("📋 用户同意管理")

current_consent = check_consent_status()
status_color = "green" if current_consent else "red"
st.markdown(f"**当前状态**: <span style='color:{status_color};'> {'✅ 已同意' if current_consent else '❌ 未同意'}</span>",
            unsafe_allow_html=True)

col_c1, col_c2 = st.columns(2)
with col_c1:
    if not current_consent:
        if st.button("✅ 同意隐私政策", type="primary", use_container_width=True):
            save_consent(True)
            st.success("感谢！已记录您的同意")
            st.rerun()
    else:
        st.button("✅ 已同意（点击刷新状态）", disabled=True, use_container_width=True)

with col_c2:
    if current_consent:
        if st.button("🚫 撤回同意", type="secondary", use_container_width=True):
            st.warning("⚠️ 撤回同意将停止所有扫描并清除历史数据！")
            confirm = st.text_input("输入 `WITHDRAW` 确认撤回")
            if confirm == "WITHDRAW":
                save_consent(False)
                st.error("同意已撤回。请手动删除 data/ 目录下的数据库文件以完全清除数据。")
                st.stop()

st.divider()

st.subheader("🗄️ 数据库管理")

try:
    db_export = Database('data/devices.db')
except:
    db_export = None

col_db1, col_db2, col_db3 = st.columns(3)

with col_db1:
    st.markdown("**🧹 数据清理**")
    st.caption(f"当前保留期: {privacy_config['retention_days']} 天")

    if st.button("清理过期数据", use_container_width=True, type="secondary"):
        st.session_state['show_cleanup_confirm'] = True

    if st.session_state.get('show_cleanup_confirm'):
        with st.container(border=True):
            st.error("⚠️ 此操作不可恢复！")
            confirm_text = st.text_input("输入 `DELETE` 确认", key="cleanup_confirm")
            col_c1, col_c2 = st.columns(2)
            with col_c1:
                if st.button("确认删除", type="primary", key="do_cleanup"):
                    if confirm_text == "DELETE":
                        try:
                            if db_export:
                                cutoff = (datetime.now() - timedelta(days=privacy_config['retention_days'])).isoformat()
                                st.success("✅ 清理完成（演示）")
                            else:
                                st.error("数据库连接失败")
                            st.session_state['show_cleanup_confirm'] = False
                            st.rerun()
                        except Exception as e:
                            st.error(f"清理失败: {str(e)}")
                    else:
                        st.error("确认码错误")
            with col_c2:
                if st.button("取消", key="cancel_cleanup"):
                    st.session_state['show_cleanup_confirm'] = False
                    st.rerun()

with col_db2:
    st.markdown("**📤 数据导出**")
    export_format = st.selectbox("格式", ["JSON", "SQLite备份"], key="export_fmt")

    if st.button("导出数据", use_container_width=True, key="export_btn"):
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        try:
            if export_format == "JSON":
                data = []
                error_occurred = False
                error_message = ""

                try:
                    if not os.path.exists('data/devices.db'):
                        error_message = "数据库文件不存在"
                        error_occurred = True
                    else:
                        try:
                            temp_db = Database('data/devices.db')
                            raw_data = temp_db.get_all_devices()

                            if raw_data is None:
                                data = []
                            elif isinstance(raw_data, list):
                                data = raw_data
                            elif isinstance(raw_data, dict):
                                data = [raw_data]
                            elif isinstance(raw_data, str):
                                try:
                                    parsed = json.loads(raw_data)
                                    data = parsed if isinstance(parsed, list) else [parsed]
                                except json.JSONDecodeError:
                                    error_message = "数据库中的JSON格式无效"
                                    error_occurred = True
                                    data = []
                            else:
                                error_message = f"未知数据类型: {type(raw_data)}"
                                error_occurred = True
                                data = []

                        except Exception as inner_e:
                            error_message = str(inner_e)
                            error_occurred = True
                            data = []

                except Exception as outer_e:
                    error_message = str(outer_e)
                    error_occurred = True
                    data = []

                json_bytes = json.dumps(data, ensure_ascii=False, indent=2).encode('utf-8')

                if len(data) == 0:
                    if error_occurred:
                        st.warning(f"⚠️ {error_message}，导出空文件")
                    else:
                        st.info("ℹ️ 数据库为空，导出空文件")
                else:
                    st.success(f"✅ 共 {len(data)} 条记录准备就绪")

                st.download_button(
                    label=f"⬇️ 下载 {'(空)' if len(data) == 0 else ''} JSON 文件",
                    data=json_bytes,
                    file_name=f"export_{timestamp}.json",
                    mime="application/json",
                    key=f"download_json_{timestamp}"
                )

            elif export_format == "SQLite备份":
                if os.path.exists('data/devices.db'):
                    with open('data/devices.db', 'rb') as f:
                        db_bytes = f.read()
                    st.download_button(
                        label="⬇️ 下载数据库备份",
                        data=db_bytes,
                        file_name=f"backup_{timestamp}.db",
                        mime="application/octet-stream",
                        key=f"download_db_{timestamp}"
                    )
                    st.success("✅ 数据库备份已准备好")
                else:
                    st.error("❌ 数据库文件不存在")
                    st.info("💡 系统将自动创建数据库文件，请先添加一些设备数据")

        except Exception as e:
            st.error(f"导出过程发生错误: {str(e)}")
            import traceback

            with st.expander("查看详细错误信息（调试用）"):
                st.code(traceback.format_exc())

with col_db3:
    st.markdown("**📥 配置备份**")

    if st.button("备份当前配置", use_container_width=True):
        backup_name = f"config_backup_{datetime.now().strftime('%Y%m%d')}.json"
        all_config = {
            "scan": scan_config, "privacy": privacy_config,
            "backup_time": datetime.now().isoformat()
        }
        with open(backup_name, 'w', encoding='utf-8') as f:
            json.dump(all_config, f, ensure_ascii=False, indent=2)
        st.success(f"已备份: {backup_name}")

    uploaded_file = st.file_uploader("导入配置", type=['json'], key="config_import")
    if uploaded_file is not None:
        try:
            imported = json.load(uploaded_file)
            if st.button("应用导入的配置", type="primary"):
                if 'scan' in imported:
                    save_config(SCAN_CONFIG_FILE, imported['scan'])
                if 'privacy' in imported:
                    save_config(PRIVACY_CONFIG_FILE, imported['privacy'])
                st.success("✅ 配置已应用，请刷新页面")
        except Exception as e:
            st.error(f"导入失败: {str(e)}")

st.divider()

st.subheader("📋 系统信息")
st.markdown("""
**IoT Vulnerability Scanner v1.0**
- 基于 Python 的智能家居安全检测框架
- 支持 CVE 漏洞匹配、POC 验证、隐私合规保护
""")

st.markdown("**🔒 合规状态检查**")
checks = []
if privacy_config.get('enable_anonymization'):
    checks.append("✅ 数据匿名化已启用")
else:
    checks.append("❌ 数据匿名化未启用")

if privacy_config.get('consent_required'):
    checks.append("✅ 用户同意机制已启用")
else:
    checks.append("❌ 用户同意机制未启用")

if check_consent_status():
    checks.append("✅ 当前用户已同意隐私政策")
else:
    checks.append("❌ 当前用户尚未同意隐私政策")

for check in checks:
    st.caption(check)

st.divider()
st.info("💡 提示：使用 **左侧侧边栏** 可切换到其他页面")

st.caption(f"© 2026 IoT Scanner | 配置最后更新: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}")