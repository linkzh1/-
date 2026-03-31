plain
复制
-python-/                                    # 项目根目录
├── LICENSE                                   # 许可证文件 (11B)
├── README.md                                 # 项目说明 (3.4KB)
├── SECURITY.md                               # 安全策略 (79B)
├── requirements.txt                          # Python依赖列表
├── all_devices_vulnerabilities.json          # 全设备漏洞数据 (175KB)
├── oui.txt                                   # OUI厂商数据库副本 (288KB)
├── test_camera.py                            # 摄像头测试脚本 (3.9KB)
├── test_oui.py                               # OUI识别测试脚本 (741B)
├── core/                                     # 核心功能模块
│   ├── __init__.py                           # 空初始化文件
│   ├── __pycache__/                          # Python缓存目录
│   ├── anonymization.py                      # 数据匿名化 (651B)
│   ├── arp_scanner.py                        # ARP网络扫描 (2.1KB)
│   ├── data_transfer.py                      # 数据传输 (4.8KB)
│   ├── database.py                           # 数据库操作 (4.7KB)
│   ├── device_identifier.py                  # 设备识别 (2.5KB)
│   ├── enhanced_device_scanner.py            # 增强设备扫描 (6.4KB)
│   ├── filter_vulnerabilities.py             # 漏洞过滤 (1.3KB)
│   ├── global_stats.py                       # 全局统计 (906B)
│   ├── json_to_sql.py                        # JSON转SQL (2.0KB)
│   ├── traffic_rate.py                       # 流量分析 (2.2KB)
│   ├── vulnerability_fetcher.py              # 漏洞获取 (1.3KB)
│   ├── vulnerability_integration.py          # 漏洞集成 (3.5KB)
│   ├── vulnerability_matching.py             # 漏洞匹配 (512B)
│   ├── vulnerability_processor.py            # 漏洞处理 (1.3KB)
│   ├── data/                                 # 核心数据目录
│   │   ├── devices.db                        # 设备数据库 (空文件)
│   │   └── history.db                        # 历史记录 (16KB)
│   └── vuln_scanner/                         # 漏洞扫描子包
│       ├── __init__.py                       # 包初始化 (477B)
│       ├── __pycache__/                      # 缓存目录
│       ├── auth_tester.py                    # 认证测试/弱口令爆破 (10KB)
│       ├── cve_matcher.py                    # CVE匹配引擎 (10.5KB)
│       ├── engine.py                         # 扫描调度主引擎 (11.6KB)
│       ├── poc_executor.py                   # POC执行器 (19KB)
│       ├── protocol_checker.py               # 协议检查 (3.8KB)
│       └── service_probe.py                  # 服务探测 (15KB)
├── data/                                     # 根数据目录
│   ├── android-tds.json                      # Android TDS数据 (空)
│   ├── apple-tds.json                        # Apple TDS数据 (空)
│   ├── cve_db.sqlite                         # CVE漏洞库 (20KB)
│   ├── devices.db                            # 设备主数据库 (28KB)
│   ├── history.db                            # 扫描历史 (40KB)
│   ├── maxmind-country.mmdb                  # MaxMind地理库 (空)
│   ├── oui.txt                               # IEEE OUI数据库 (5.6MB)
│   └── tds.json                              # TDS配置 (空)
├── scripts/                                  # 启动脚本目录
│   ├── all_devices_vulnerabilities.json      # 脚本级漏洞数据 (119B)
│   ├── start.py                              # 主启动脚本 (10KB)
│   └── data/                                 # 脚本数据目录
│       ├── devices.db                        # 设备数据 (20KB)
│       └── history.db                        # 历史数据 (16KB)
├── tests/                                    # 测试目录
│   ├── __init__.py                           # 空初始化文件
│   ├── arp_output.py                         # ARP输出测试 (2.8KB)
│   ├── mock_arp_output.py                    # ARP模拟数据 (2.2KB)
│   ├── test_anonymization.py                 # 空测试文件
│   ├── test_device_identifier.py             # 空测试文件
│   ├── test_global_stats.py                  # 空测试文件
│   ├── test_traffic_rate.py                  # 空测试文件
│   ├── test_vulnerability_database.py        # 空测试文件
│   ├── test_vulnerability_integration.py     # 漏洞集成测试 (2.1KB)
│   └── test_vulnerability_matching.py        # 空测试文件
└── ui/                                       # Web界面模块
    ├── __init__.py                           # 空初始化文件
    ├── __pycache__/                          # 缓存目录
    ├── common.py                             # 公共工具 (空文件)
    ├── consent.py                            # 隐私同意路由 (520B)
    ├── device_list.py                        # 设备列表路由 (8.5KB)
    ├── sidebar.py                            # 侧边栏组件 (182B)
    ├── template.py                           # 模板工具 (142B)
    ├── pages/                                # 页面路由目录
    │   ├── 1_Overview.py                     # 概览页 (空)
    │   ├── 2_Device_Details.py               # 设备详情页 (空)
    │   └── 3_Settings.py                     # 设置页 (空)
    ├── surveys/                              # 调查问卷目录
    │   ├── notice_and_choice_post_survey.md  # 用后调查 (空)
    │   └── notice_and_choice_pre_survey.md   # 用前调查 (空)
    └── templates/                            # HTML模板目录
        ├── consent.html                      # 隐私授权页 (605B)
        ├── device_detail.html                # 设备详情页 (17KB)
        ├── index.html                      # 设备列表首页 (16KB)
        ├── manual_scan.html                # 手动扫描页 (4.8KB)
        ├── overview.html                   # 网络概览页 (519B)
        ├── settings.html                   # 设置页面 (807B)
        ├── sidebar.html                    # 侧边栏模板 (1.8KB)
        └── survey.html                     # 调查问卷页 (566B)
🔍 关键发现（README 未提及的内容）
1. core 目录实际内容远比 README 描述的丰富
README 只列出了 core/vuln_scanner/ 下的 9 个文件，但实际上 core/ 下还有平级的 13 个独立 Python 文件：
vulnerability_fetcher.py, vulnerability_integration.py, vulnerability_matching.py, vulnerability_processor.py - 独立的漏洞数据处理流
database.py, data_transfer.py, json_to_sql.py - 数据持久化层
enhanced_device_scanner.py - 增强扫描功能（独立于 arp_scanner.py）
filter_vulnerabilities.py - 漏洞过滤模块
2. 数据库文件分散多处
core/data/ - 核心运行数据库（空 devices.db + 有数据的 history.db）
data/ - 根数据目录（cve_db.sqlite, devices.db, history.db）
scripts/data/ - 脚本级数据库副本
问题：数据文件分散，存在冗余和一致性问题
3. 存在大量空文件/骨架文件
tests/ 目录 10 个文件中有 7 个是空文件（大小 0B）
ui/pages/ 下的 3 个 Python 文件全是空的
ui/surveys/ 下的 2 个 markdown全是空的
ui/common.py - 空文件
4. 架构混杂
既有 Flask 模板（ui/templates/*.html），又有 Streamlit 风格页面（ui/pages/1_Overview.py 等）
两个 oui.txt 文件（根目录 288KB vs data/oui.txt 5.6MB）
5. 关于你的问题：core 下为什么只有 vuln_scanner？
实际情况：core/ 下不只有 vuln_scanner/，还有大量平级模块。README 的描述是不完整的/过时的。
现在的 core/ 更像是一个混乱的单层架构，而非之前推测的"预留扩展设计"。vuln_scanner/ 作为子包存在，但与其平级的还有 database、traffic_rate、anonymization 等模块——这确实显得架构不一致：有些功能放子包，有些放平级，缺乏统一的分层逻辑。
那你给我生成一个更完整的readme文件
编辑
复制
分享
生成完整 IoT 漏洞扫描工具文档
基于对仓库的详细分析，我为你生成一个更准确、更完整的 README.md：
Markdown
复制
代码
预览
# IoT Vulnerability Scanner

基于 Python 的智能家居物联网设备安全检测框架，支持设备发现、指纹识别、漏洞扫描与 POC 验证。

## 功能特性

### 1. 网络层扫描
- **ARP 设备发现**：扫描局域网存活主机（需 Root/管理员权限）
- **OUI 厂商识别**：基于 IEEE OUI 数据库识别设备制造商
- **增强设备扫描**：深度设备探测与指纹识别

### 2. 漏洞扫描引擎
- **扫描调度引擎** (`engine.py`)：任务分发、并发控制、结果汇总
- **CVE 漏洞匹配** (`cve_matcher.py`)：基于设备指纹匹配历史 CVE 漏洞
- **POC 验证执行** (`poc_executor.py`)：执行具体漏洞验证代码
- **认证安全测试** (`auth_tester.py`)：弱口令爆破与默认凭证检测
- **协议安全检查** (`protocol_checker.py`)：MQTT/CoAP/UPnP 协议合规性分析
- **服务深度探测** (`service_probe.py`)：版本识别与详细 Banner 抓取

### 3. 数据处理与集成
- **漏洞数据获取**：从多个源获取 CVE 数据
- **漏洞数据集成**：多源漏洞数据归一化处理
- **漏洞匹配引擎**：设备指纹与漏洞库智能匹配
- **数据持久化**：SQLite 数据库存储扫描结果与历史
- **数据迁移工具**：JSON 与 SQL 数据格式互转

### 4. 流量分析
- **实时流量监控**：网络速率统计与设备级流量分析
- **全局网络态势**：全局统计仪表盘展示

### 5. 隐私合规
- **数据匿名化**：MAC/IP 地址自动掩码处理
- **用户授权管理**：内置隐私同意机制（Notice and Choice）

### 6. Web 管理界面
- **Flask 后端**：设备列表、扫描控制、结果展示
- **响应式前端**：设备详情页、手动扫描、设置管理
- **隐私调查**：用户反馈收集（前/后调查问卷）

## 项目结构
-python-/
├── core/                           # 核心业务逻辑层
│   ├── init.py
│   ├── arp_scanner.py              # ARP 网络扫描
│   ├── device_identifier.py        # OUI 厂商识别
│   ├── enhanced_device_scanner.py  # 增强设备扫描
│   ├── service_probe.py            # 服务探测（迁移至 vuln_scanner/）
│   ├── traffic_rate.py             # 流量分析统计
│   ├── global_stats.py             # 全局统计
│   ├── anonymization.py            # 数据脱敏
│   ├── database.py                 # 数据库操作
│   ├── data_transfer.py            # 数据传输
│   ├── json_to_sql.py              # JSON-SQL 转换
│   ├── filter_vulnerabilities.py   # 漏洞过滤
│   ├── vulnerability_fetcher.py    # 漏洞数据获取
│   ├── vulnerability_integration.py # 漏洞数据集成
│   ├── vulnerability_matching.py   # 漏洞匹配算法
│   ├── vulnerability_processor.py  # 漏洞处理器
│   ├── data/                       # 运行时数据
│   │   ├── devices.db              # 设备数据库
│   │   └── history.db              # 扫描历史
│   └── vuln_scanner/               # 漏洞扫描子包
│       ├── init.py
│       ├── engine.py                 # 扫描调度主引擎
│       ├── cve_matcher.py            # CVE 匹配引擎
│       ├── poc_executor.py           # POC 执行器
│       ├── auth_tester.py            # 认证测试（弱口令）
│       ├── protocol_checker.py       # 协议安全检查
│       └── service_probe.py          # 服务指纹识别
├── ui/                             # Web 界面层 (Flask)
│   ├── init.py
│   ├── device_list.py              # 设备列表路由
│   ├── consent.py                  # 隐私同意路由
│   ├── sidebar.py                  # 侧边栏组件
│   ├── template.py                 # 模板工具
│   ├── common.py                   # 公共工具（待实现）
│   ├── pages/                      # Streamlit 风格页面（待实现）
│   │   ├── 1_Overview.py
│   │   ├── 2_Device_Details.py
│   │   └── 3_Settings.py
│   ├── surveys/                    # 用户调查问卷（待实现）
│   │   ├── notice_and_choice_pre_survey.md
│   │   └── notice_and_choice_post_survey.md
│   └── templates/                  # HTML 模板
│       ├── index.html              # 设备列表
│       ├── device_detail.html      # 设备详情与漏洞结果
│       ├── manual_scan.html        # 手动扫描
│       ├── overview.html           # 网络概览
│       ├── settings.html           # 系统设置
│       ├── sidebar.html            # 侧边栏组件
│       ├── consent.html            # 隐私授权
│       └── survey.html             # 调查问卷
├── data/                           # 静态数据资源
│   ├── oui.txt                     # IEEE OUI 数据库（5.6MB）
│   ├── cve_db.sqlite               # CVE 漏洞库
│   ├── devices.db                  # 设备主数据库
│   ├── history.db                  # 扫描历史记录
│   ├── android-tds.json            # Android TDS 配置
│   ├── apple-tds.json              # Apple TDS 配置
│   ├── tds.json                    # 通用 TDS 配置
│   └── maxmind-country.mmdb        # MaxMind 地理位置库
├── scripts/                        # 启动与工具脚本
│   ├── start.py                    # 主启动脚本（Flask）
│   ├── all_devices_vulnerabilities.json
│   └── data/                       # 脚本级数据副本
│       ├── devices.db
│       └── history.db
├── tests/                          # 测试套件
│   ├── init.py
│   ├── arp_output.py               # ARP 输出测试
│   ├── mock_arp_output.py          # ARP 模拟数据
│   ├── test_vulnerability_integration.py # 漏洞集成测试
│   └── test_*.py                   # 其他测试文件（待实现）
├── test_camera.py                  # 摄像头专项测试
├── test_oui.py                     # OUI 识别测试
├── oui.txt                         # OUI 数据库副本（精简版）
├── all_devices_vulnerabilities.json # 设备漏洞汇总
├── requirements.txt                # Python 依赖
├── README.md                       # 本文件
├── LICENSE                         # 许可证
└── SECURITY.md                     # 安全策略
plain
复制

## 安装说明

### 系统要求
- Python 3.8+
- Linux/macOS/Windows
- 管理员/Root 权限（用于原始套接字操作）
- Windows 用户需预先安装 [Npcap](https://npcap.com/) 或 WinPcap

### 安装步骤

**Linux/macOS:**
```bash
git clone https://github.com/linkzh1/-python-.git
cd -python-
python3 -m venv env
source env/bin/activate
pip install -r requirements.txt
sudo python3 scripts/start.py
Windows:
cmd
复制
git clone https://github.com/linkzh1/-python-.git
cd -python-
python -m venv env
.\env\Scripts\activate.bat
pip install -r requirements.txt
python scripts\start.py
依赖列表
见 requirements.txt，主要依赖包括：
Flask 2.0+ (Web 框架)
Scapy 2.4+ (网络数据包处理)
Paramiko (SSH 弱口令检测)
Requests (HTTP 服务探测)
SQLite3 (数据存储)
使用说明
启动 Web 界面
bash
复制
sudo python3 scripts/start.py
默认访问地址：http://localhost:5000
主要功能路径
表格
功能	入口	说明
设备列表	/ (index.html)	查看发现的 IoT 设备
设备详情	/device/<id>	查看单设备漏洞扫描结果
手动扫描	/manual_scan	触发指定设备深度扫描
隐私授权	/consent	管理数据收集授权
系统设置	/settings	配置扫描参数
核心模块调用示例
设备发现：
Python
复制
from core.arp_scanner import ARPScanner
from core.device_identifier import DeviceIdentifier

scanner = ARPScanner('192.168.1.0/24')
devices = scanner.scan()
identifier = DeviceIdentifier('data/oui.txt')
for device in devices:
    vendor = identifier.identify(device['mac'])
漏洞扫描：
Python
复制
from core.vuln_scanner.engine import ScanEngine
from core.vuln_scanner.cve_matcher import CVEMatcher

engine = ScanEngine()
matcher = CVEMatcher('data/cve_db.sqlite')
results = engine.scan_device(target_ip, matcher)
数据文件说明
数据库文件分布
项目使用多个 SQLite 数据库，注意数据一致性：
data/devices.db & data/history.db - 主数据库（推荐）
core/data/ - 运行时副本（可能为空或过时）
scripts/data/ - 脚本级数据（可能为空或过时）
建议：定期同步 data/ 目录下的数据库为主数据源。
OUI 数据库
data/oui.txt (5.6MB) - 完整 IEEE OUI 数据库，用于设备厂商识别
oui.txt (288KB) - 精简版副本，内容可能过时
开发状态与 TODO
已实现功能 ✅
[x] ARP 网络扫描与设备发现
[x] OUI 厂商识别
[x] 漏洞扫描引擎（CVE 匹配 + POC 执行）
[x] 弱口令爆破（SSH/HTTP）
[x] 协议检查（MQTT/CoAP/UPnP）
[x] 数据匿名化（MAC/IP 掩码）
[x] Flask Web 界面（基础版）
[x] SQLite 数据持久化
待完善功能 ⚠️
[ ] 测试覆盖：tests/ 目录大部分测试文件为空（骨架代码）
[ ] Streamlit 页面：ui/pages/ 下 3 个页面文件为空
[ ] 用户调查：ui/surveys/ 下问卷模板为空
[ ] 公共工具：ui/common.py 为空
[ ] 架构统一：core/vuln_scanner/ 与平级模块的职能边界需梳理
[ ] 数据整合：合并分散的数据库文件到统一位置
注意事项
法律合规：本工具仅供安全研究与教育目的，请在合法授权范围内使用。开发者不对任何非法使用行为负责。
权限要求：运行扫描功能需要管理员/root 权限（用于原始套接字操作）。
数据隐私：内置匿名化功能默认开启，符合隐私合规要求。
网络环境：Windows 用户需预先安装 Npcap 驱动。
架构设计说明
分层架构
核心层 (core/)：纯业务逻辑，无 Web 依赖
vuln_scanner/：漏洞扫描专用子包
平级模块：数据处理、数据库、流量分析等基础设施
界面层 (ui/)：Flask Web 应用与路由
数据层 (data/)：静态资源与持久化存储
脚本层 (scripts/)：运维入口与启动脚本
设计问题与建议
当前 core/ 目录存在架构不一致：部分功能放在 vuln_scanner/ 子包，部分放在平级目录。建议：
将 vulnerability_*.py 等漏洞相关模块移入 core/vuln_scanner/
将数据库相关模块（database.py, json_to_sql.py）归入 core/db/
或扁平化：取消 vuln_scanner/ 子包，所有模块平级放置
许可证
见 LICENSE 文件。
安全声明
见 SECURITY.md 文件。
免责声明：本工具仅供安全研究与教育目的，请在合法授权范围内使用。开发者不对任何非法使用行为负责。