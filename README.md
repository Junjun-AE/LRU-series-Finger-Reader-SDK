# 🔐 LRU Series Fingerprint Reader Management System
# 🔐 LRU系列指纹读头管理系统

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](https://www.microsoft.com/windows)
[![Version: 5.1](https://img.shields.io/badge/version-5.1-orange.svg)](https://github.com/yourusername/fingerprint-system/releases)

---

**Professional Edition v5.1 | 专业版 v5.1**

A comprehensive fingerprint reader management system designed for enterprise environments. Features a modern dashboard interface, secure data encryption, multi-level permission management, and robust device control.

专为企业环境设计的综合性指纹读头管理系统。配备现代化仪表板界面、安全数据加密、多级权限管理和强大的设备控制功能。

---

## 📋 Table of Contents | 目录

- [✨ Key Features | 主要特性](#-key-features--主要特性)
- [🛠️ Technical Stack | 技术栈](#️-technical-stack--技术栈)
- [📦 Installation | 安装](#-installation--安装)
- [📁 Project Structure | 项目结构](#-project-structure--项目结构)
- [🚀 Usage Guide | 使用指南](#-usage-guide--使用指南)
- [⚙️ Configuration | 配置](#️-configuration--配置)
- [🔒 Security Notes | 安全说明](#-security-notes--安全说明)
- [📝 Requirements | 依赖清单](#-requirements--依赖清单)
- [🤝 Contributing | 贡献](#-contributing--贡献)
- [📄 License | 许可证](#-license--许可证)
- [📧 Contact | 联系方式](#-contact--联系方式)
- [🙏 Acknowledgements | 致谢](#-acknowledgements--致谢)

---

## ✨ Key Features | 主要特性

### 🔐 Security & Reliability | 安全与可靠性

| Feature | Description | 特性 | 描述 |
|---------|-------------|------|------|
| **Thread-safe Operations** | All GUI operations executed in main thread | **线程安全操作** | 所有GUI操作在主线程执行 |
| **Secure Encryption** | AES-256 encryption for sensitive fingerprint data | **安全加密** | 对敏感指纹数据采用AES-256加密 |
| **Automatic Backups** | Self-cleaning backup mechanism with configurable retention | **自动备份** | 自清理备份机制，支持配置保留数量 |
| **Comprehensive Logging** | Detailed activity tracking with rotation support | **完整日志** | 详细的活动跟踪，支持日志轮转 |

### 🎨 Modern UI | 现代化界面

| Feature | Description | 特性 | 描述 |
|---------|-------------|------|------|
| **Dashboard Overview** | Real-time statistics and activity monitoring | **仪表板概览** | 实时统计和活动监控 |
| **Custom Components** | Modern buttons, cards, and themed widgets | **自定义组件** | 现代化按钮、卡片和主题控件 |
| **Responsive Design** | Adaptive layout with smooth transitions | **响应式设计** | 自适应布局，平滑过渡 |
| **Dark Theme** | Eye-friendly dark theme for extended use | **深色主题** | 适合长时间使用的护眼主题 |

### 📋 Core Functionality | 核心功能

| Feature | Description | 特性 | 描述 |
|---------|-------------|------|------|
| **Fingerprint Enrollment** | Multi-pass enrollment with quality checks | **指纹登记** | 多次按压登记，质量检查 |
| **Real-time Identification** | Fast matching against database | **实时识别** | 快速数据库匹配 |
| **User Management** | CRUD operations with permission levels (1-4) | **用户管理** | 支持权限等级(1-4)的增删改查 |
| **Data Import/Export** | Encrypted JSON format with password protection | **数据导入/导出** | 加密JSON格式，密码保护 |

### 🔧 Device Management | 设备管理

| Feature | Description | 特性 | 描述 |
|---------|-------------|------|------|
| **DLL Safety** | Secure loading mechanism for fingerprint reader drivers | **DLL安全** | 指纹读头驱动的安全加载机制 |
| **Device Status** | Real-time connection monitoring | **设备状态** | 实时连接监控 |
| **Model Detection** | Automatic device information retrieval | **型号检测** | 自动获取设备信息 |
| **Error Recovery** | Graceful handling of device disconnections | **错误恢复** | 设备断连的优雅处理 |

---

## 🛠️ Technical Stack | 技术栈

| Component | Technology | 组件 | 技术 |
|-----------|------------|------|------|
| **Language** | Python 3.8+ | **语言** | Python 3.8+ |
| **GUI Framework** | Tkinter with custom theming | **GUI框架** | Tkinter + 自定义主题 |
| **Encryption** | Cryptography (Fernet) + Base64 fallback | **加密** | Cryptography (Fernet) + Base64备用 |
| **Threading** | Thread-safe operations with queue management | **多线程** | 带队列管理的线程安全操作 |
| **Packaging** | PyInstaller for standalone executable | **打包** | PyInstaller生成独立可执行文件 |

---

## 📦 Installation | 安装

### Prerequisites | 前置要求

- **Windows 10/11 (64-bit)**
- **Python 3.8+** (for development)
- **LRU Series fingerprint reader hardware**

### Quick Start | 快速开始

# Clone repository | 克隆仓库
git clone https://github.com/yourusername/fingerprint-system.git
cd fingerprint-system

# Install dependencies | 安装依赖
pip install -r requirements.txt

# Run application | 运行应用
python Fingerprint_login.py
PyInstaller Build | 打包构建
bash
# Generate executable | 生成可执行文件
pyinstaller --onefile --windowed ^
  --name "指纹管理系统" ^
  --add-data "nbis64.dll;." ^
  --add-data "fpcorex64.dll;." ^
  --add-data "fpengine.dll;." ^
  Fingerprint_login.py
Note for PowerShell users: Replace ^ with ` for line continuation.

📁 Project Structure | 项目结构
text
fingerprint-system/
├── 📄 Fingerprint_login.py      # Main application entry
├── 📄 requirements.txt         # Python dependencies
├── 📄 README.md                # This file
├── 📄 LICENSE                  # MIT License
├── 📦 nbis64.dll               # Fingerprint reader driver
├── 📦 fpcorex64.dll            # Fingerprint reader driver
├── 📦 fpengine.dll             # Fingerprint reader driver
└── 📁 fingerprint_data/        # Data directory (created at runtime)
    ├── 📄 fingerprints.dat     # Encrypted fingerprint database
    └── 📁 backups/             # Automatic backups
🚀 Usage Guide | 使用指南
🔑 Login | 登录
Default credentials: admin / admin

Change password upon first login

默认账号：admin / admin

首次登录后请修改密码

🔌 Device Setup | 设备设置
Connect fingerprint reader via USB | 通过USB连接指纹读头

Install drivers if required | 如需要，安装驱动程序

Click "Connect Device" in Device Management | 在设备管理中点击"连接设备"

✋ Enrollment | 登记指纹
Navigate to "Fingerprint Enrollment" | 进入"指纹登记"页面

Enter user name and permission level | 输入用户名和权限等级

Follow on-screen instructions for fingerprint placement | 按照屏幕提示放置手指

Multiple scans ensure template quality | 多次扫描确保模板质量

🔍 Identification | 识别指纹
Click "Start Identification" | 点击"开始识别"

Place finger on reader | 将手指放在读头上

System displays matching user information | 系统显示匹配的用户信息

⚙️ Configuration | 配置
Key configuration options in code | 代码中的关键配置选项：

python
# Encryption password (change for production)
# 加密密码（生产环境请修改）
self.data_manager = FingerprintDataManager(
    encryption_password="MySecurePassword2024!"
)

# Backup retention | 备份保留设置
MAX_BACKUPS = 10
MAX_ACTIVITY_LOG = 100
🔒 Security Notes | 安全说明
English	中文
Change default password: Update the default admin password	修改默认密码：更新默认管理员密码
Encryption key: Modify the encryption password in production	加密密钥：在生产环境中修改加密密码
Data backups: Backups are automatically maintained in backups/	数据备份：备份自动保存在 backups/ 目录
Secure distribution: Never commit DLLs to public repositories without consideration	安全分发：谨慎考虑将DLL文件提交到公共仓库
📝 Requirements | 依赖清单
txt
cryptography>=3.4.8
pyinstaller>=4.5.1  # for building | 用于打包
Create a requirements.txt file with the above content.

创建包含以上内容的 requirements.txt 文件。

🤝 Contributing | 贡献
Contributions are welcome! Please feel free to submit a Pull Request.

欢迎贡献！请随时提交Pull Request。

Fork the Project | Fork 项目

Create your Feature Branch | 创建特性分支 (git checkout -b feature/AmazingFeature)

Commit your Changes | 提交更改 (git commit -m 'Add some AmazingFeature')

Push to the Branch | 推送到分支 (git push origin feature/AmazingFeature)

Open a Pull Request | 开启Pull Request

📄 License | 许可证
This project is licensed under the MIT License - see the LICENSE file for details.

本项目采用MIT许可证 - 查看 LICENSE 文件了解详情。

text
MIT License

Copyright (c) 2026 [Your Name]

Permission is hereby granted...
📧 Contact | 联系方式
Author | 作者: [朱君]

Email | 邮箱: [1323412519@qq.com]


🙏 Acknowledgements | 致谢
LRU Series Fingerprint Reader Hardware Documentation

Python Cryptography Library Contributors

Tkinter Community

PyInstaller Documentation

📊 Version History | 版本历史
v5.1 (2026-03-09)

Thread-safe GUI operations

Enhanced error handling

Modern dashboard UI

Automatic backup cleanup

v5.0 (2025-12-01)

Initial professional release

Multi-level permission system

Encrypted data storage

⚠️ Important Notes | 重要说明
⚠️ WARNING: This software interfaces directly with fingerprint reader hardware. Ensure you have the proper authorization and comply with all applicable privacy laws and regulations before deployment.

⚠️ 警告：本软件直接与指纹读头硬件交互。在部署前，请确保您拥有适当的授权并遵守所有适用的隐私法律和法规。

Made with ❤️ for enterprise security
为企业安全而设计

<div align="center"> <sub>Built with Python and Tkinter | 使用 Python 和 Tkinter 构建</sub> <br> <sub>Copyright © 2026 [Your Name]. All rights reserved.</sub> </div> ```
📝 配套文件
1. requirements.txt
txt
cryptography>=3.4.8
pyinstaller>=4.5.1
2. LICENSE (MIT)
txt
MIT License

Copyright (c) 2026 [Your Name]

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
3. .gitignore
gitignore
# Python
__pycache__/
*.py[cod]
*.pyc
*.pyo
*.pyd
.Python

# Virtual Environment
venv/
env/
ENV/
env.bak/
venv.bak/

# IDE
.vscode/
.idea/
*.swp
*.swo

# Project specific
fingerprint_data/
*.log
*.dat
build/
dist/
*.spec

# Backups
*.bak
📦 打包命令（已提供）
bash
cd C:\Users\Administrator\Desktop\指纹登陆
pyinstaller --onefile --windowed --name "指纹管理系统" --add-data "fpengine.dll;." --add-data "fpcorex64.dll;." --add-data "nbis64.dll;." 指纹登陆_packaged.py
这个README.md包含了：

✅ 完整的中英双语对照

✅ 专业的Markdown格式

✅ 表格化特性展示

✅ 清晰的使用指南

✅ 安全说明和警告

✅ 贡献指南

✅ 许可证信息

✅ 联系方式

需要我调整任何部分吗？
