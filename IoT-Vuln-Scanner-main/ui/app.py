# ui/app.py
import streamlit as st

st.set_page_config(
    page_title="IoT 漏洞扫描系统",
    page_icon="🌐",
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

# 显示欢迎页，不自动跳转（让用户看到侧边栏导航）
st.title("🌐 IoT 漏洞扫描系统")
st.info("👈 请从左侧边栏选择功能页面")

st.markdown("""
### 功能模块
- **网络概览**：查看全局设备状态、流量监控、漏洞趋势
- **设备详情**：查看单个设备信息、执行深度扫描、查看漏洞
- **系统设置**：配置扫描参数、隐私设置、数据管理
- **问卷**：填写IoT安全评估问卷、获取安全建议、生成合规报告
""")

# 左侧中文导航（可点击跳转）
with st.sidebar:
    st.markdown("### 🧭 功能导航")

    # 当前页面（首页）
    st.page_link("app.py", label="🏠 首页", icon="🏠", disabled=True)

    # 其他功能页面（可点击跳转）
    st.page_link("pages/1_Overview.py", label="📊 网络概览", icon="📊")
    st.page_link("pages/2_Device_Details.py", label="💻 设备详情", icon="💻")
    st.page_link("pages/3_Settings.py", label="⚙️ 系统设置", icon="⚙️")
    st.page_link("pages/4_Survey.py", label="📝 问卷", icon="📝")

    st.divider()
    st.caption("🔄 当前页面：首页")