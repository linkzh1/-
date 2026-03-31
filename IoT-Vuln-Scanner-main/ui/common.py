# ui\common.py
"""
UI 公共工具函数
"""

import hashlib
import time
import streamlit as st
from functools import wraps
import pandas as pd
from datetime import datetime
import json
import os

# ========== 隐私合规相关常量 ==========
PRIVACY_CONFIG_PATH = 'config/privacy_config.json'
CONSENT_FILE = 'data/user_consent.json'


# ========== 原有函数保持不变 ==========

def cache_with_ttl(seconds=300):
    """带TTL的缓存装饰器"""
    cache = {}

    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            key = str(args) + str(kwargs)
            current_time = time.time()

            if key in cache:
                result, timestamp = cache[key]
                if current_time - timestamp < seconds:
                    return result

            result = func(*args, **kwargs)
            cache[key] = (result, current_time)
            return result

        return wrapper

    return decorator


def format_mac(mac: str) -> str:
    """统一MAC地址格式"""
    mac = mac.upper().replace('-', ':').replace('.', ':')
    if len(mac) == 12:
        mac = ':'.join([mac[i:i + 2] for i in range(0, 12, 2)])
    return mac


def get_severity_color(severity: str) -> str:
    """获取严重等级对应颜色"""
    colors = {
        'Critical': '#FF0000',
        'High': '#FF6600',
        'Medium': '#FFCC00',
        'Low': '#00CC00',
        'Info': '#0066CC'
    }
    return colors.get(severity, '#808080')


def display_vulnerability_card(vuln: dict):
    """Streamlit 漏洞卡片展示组件"""
    severity = vuln.get('severity', 'Medium')
    color = get_severity_color(severity)

    st.markdown(f"""
    <div style="
        padding: 10px;
        border-left: 5px solid {color};
        background-color: #f0f2f6;
        margin: 10px 0;
        border-radius: 5px;
    ">
        <h4 style="margin:0">{vuln.get('cve_id', 'Unknown')}</h4>
        <p style="margin:5px 0"><strong>严重等级:</strong> <span style="color:{color}">{severity}</span></p>
        <p style="margin:5px 0;font-size:0.9em">{vuln.get('description', '无描述')[:200]}...</p>
    </div>
    """, unsafe_allow_html=True)


def paginate_dataframe(df: pd.DataFrame, page_size: int = 10):
    """DataFrame分页组件"""
    total_pages = len(df) // page_size + (1 if len(df) % page_size > 0 else 0)
    page = st.number_input("页码", min_value=1, max_value=max(1, total_pages), value=1)

    start_idx = (page - 1) * page_size
    end_idx = start_idx + page_size

    return df.iloc[start_idx:end_idx]


def export_to_csv(df: pd.DataFrame, filename: str):
    """导出CSV按钮"""
    csv = df.to_csv(index=False)
    st.download_button(
        label="📥 导出 CSV",
        data=csv,
        file_name=filename,
        mime='text/csv'
    )


def show_toast(message: str, type: str = "info"):
    """显示临时提示"""
    if type == "success":
        st.success(message)
    elif type == "error":
        st.error(message)
    elif type == "warning":
        st.warning(message)
    else:
        st.info(message)

    time.sleep(3)
    st.empty()


# ========== 新增：隐私合规工具函数 ==========

def load_privacy_config():
    """加载隐私配置"""
    default = {
        "enable_anonymization": True,
        "mask_level": "partial",
        "retention_days": 30,
        "consent_required": True
    }
    if os.path.exists(PRIVACY_CONFIG_PATH):
        try:
            with open(PRIVACY_CONFIG_PATH, 'r', encoding='utf-8') as f:
                return {**default, **json.load(f)}
        except:
            return default
    return default


def check_consent_status():
    """检查用户是否已同意隐私政策"""
    if not os.path.exists(CONSENT_FILE):
        return False
    try:
        with open(CONSENT_FILE, 'r', encoding='utf-8') as f:
            consent = json.load(f)
            if 'timestamp' in consent:
                agreed_time = datetime.fromisoformat(consent['timestamp'])
                if (datetime.now() - agreed_time).days > 365:
                    return False
            return consent.get('consented', False)
    except:
        return False


def save_consent(consented=True, purposes=None):
    """保存用户同意记录"""
    os.makedirs('data', exist_ok=True)
    consent_data = {
        "consented": consented,
        "timestamp": datetime.now().isoformat(),
        "purposes": purposes or ["data_collection", "scanning", "storage"],
        "version": "1.0"
    }
    with open(CONSENT_FILE, 'w', encoding='utf-8') as f:
        json.dump(consent_data, f, ensure_ascii=False, indent=2)


def show_privacy_banner():
    """显示隐私保护状态横幅（在每个页面顶部调用）"""
    config = load_privacy_config()

    # 如果强制要求同意但未同意，显示阻塞式警告
    if config.get('consent_required') and not check_consent_status():
        show_consent_notice()
        return

    # 根据配置显示不同颜色提示
    if config.get('enable_anonymization'):
        mask_type = "部分" if config.get('mask_level') == 'partial' else "完全"
        st.info(
            f"🔒 **隐私保护模式已开启** | 脱敏方式：{mask_type} | "
            f"数据保留：{config.get('retention_days', 30)}天",
            icon="🛡️"
        )
    else:
        st.warning(
            "⚠️ **隐私保护已关闭** - 敏感数据（IP/MAC）将以明文显示，建议开启匿名化。",
            icon="👁️"
        )


def show_consent_notice():
    """隐私同意提示（内联版，非弹窗）"""
    st.error("🛡️ **首次使用请同意隐私政策**", icon="🚨")
    with st.container(border=True):
        st.markdown("""
        **数据收集声明**：本工具会收集IP、MAC、开放端口等信息用于安全扫描。
        
        **保护措施**：数据仅本地存储，自动脱敏处理，30天后自动删除。
        """)
        col1, col2 = st.columns(2)
        with col1:
            if st.button("✅ 我同意", type="primary", use_container_width=True, key="btn_agree"):
                save_consent(True)
                st.success("已保存！请刷新页面")
                st.rerun()
        with col2:
            if st.button("❌ 不同意", use_container_width=True, key="btn_disagree"):
                st.error("您必须同意隐私政策才能使用本系统")
                st.stop()


def mask_device_data(device):
    """
    根据隐私配置脱敏设备数据
    返回: (masked_device, is_masked)
    """
    config = load_privacy_config()
    if not config.get('enable_anonymization'):
        return device, False  # 未脱敏

    masked = device.copy()
    ip = device.get('ip', '')
    mac = device.get('mac', '')

    # IP脱敏
    if config.get('mask_level') == 'full':
        masked['ip'] = "***.***.***" + ip[ip.rfind('.'):] if '.' in ip else "***.***.***.***"
    else:
        parts = ip.split('.')
        if len(parts) == 4:
            masked['ip'] = f"{parts[0]}.{parts[1]}.***.{parts[3]}"

    # MAC脱敏（保留OUI厂商标识）
    if ':' in mac:
        parts = mac.split(':')
        masked['mac'] = ':'.join(parts[:3]) + ':XX:XX:XX'
    elif '-' in mac:
        parts = mac.split('-')
        masked['mac'] = '-'.join(parts[:3]) + '-XX-XX-XX'

    return masked, True


def get_masked_display_value(value: str, data_type: str = 'ip') -> str:
    """
    获取脱敏后的显示值（用于单个字段）
    data_type: 'ip' 或 'mac'
    """
    config = load_privacy_config()
    if not config.get('enable_anonymization'):
        return value

    if data_type == 'ip':
        if config.get('mask_level') == 'full':
            return "***.***.***" + value[value.rfind('.'):] if '.' in value else "***.***.***.***"
        else:
            parts = value.split('.')
            if len(parts) == 4:
                return f"{parts[0]}.{parts[1]}.***.{parts[3]}"
    elif data_type == 'mac':
        if ':' in value:
            parts = value.split(':')
            return ':'.join(parts[:3]) + ':XX:XX:XX'
        elif '-' in value:
            parts = value.split('-')
            return '-'.join(parts[:3]) + '-XX-XX-XX'

    return value