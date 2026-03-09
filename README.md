# LRU 指纹读头管理系统

<div align="center">

![Version](https://img.shields.io/badge/version-5.1-blue.svg)
![Python](https://img.shields.io/badge/python-3.7+-green.svg)
![License](https://img.shields.io/badge/license-MIT-orange.svg)
![Platform](https://img.shields.io/badge/platform-Windows-lightgrey.svg)

**专业的 LRU 系列指纹读头管理系统**

现代化仪表板界面 | 多级权限管理 | 数据加密存储

</div>

---

## 📋 目录

- [功能特性](#-功能特性)
- [系统要求](#-系统要求)
- [安装说明](#-安装说明)
- [使用指南](#-使用指南)
- [配置说明](#️-配置说明)
- [开发说明](#-开发说明)
- [常见问题](#-常见问题)
- [更新日志](#-更新日志)
- [许可证](#-许可证)

---

## ✨ 功能特性

### 核心功能
- 🔐 **指纹注册与认证** - 支持多次采集,提高识别准确率
- 👥 **用户管理** - 完整的用户信息管理,支持姓名、ID、权限等级
- 🔍 **高级搜索** - 按姓名、ID、权限等级快速检索
- 📊 **数据统计** - 实时显示用户数量、各等级分布等统计信息

### 数据管理
- 💾 **数据导入/导出** - 支持 JSON 格式的数据备份与恢复
- 🔒 **数据加密** - 可选的数据文件加密,保护敏感信息
- 🔄 **自动备份** - 定期自动备份,防止数据丢失
- 🧹 **备份清理** - 智能清理过期备份文件

### 用户体验
- 🎨 **现代化界面** - 深色主题,专业的仪表板设计
- 📱 **响应式布局** - 自适应窗口大小
- 🔔 **实时反馈** - 操作状态实时显示
- 🌐 **多级权限** - 支持 4 级权限管理

### 技术特性
- ⚡ **线程安全** - 所有 GUI 操作在主线程执行
- 🛡️ **异常处理** - 完善的错误处理和日志记录
- 📦 **打包支持** - 支持 PyInstaller 打包为独立可执行文件
- 🔧 **DLL 动态加载** - 智能定位和加载指纹设备驱动

---

## 💻 系统要求

### 硬件要求
- **指纹设备**: LRU 系列指纹读头
- **内存**: 至少 2GB RAM
- **存储**: 至少 100MB 可用空间

### 软件要求
- **操作系统**: Windows 7/8/10/11 (64位)
- **Python**: 3.7 或更高版本 (开发环境)
- **依赖库**: 详见 `requirements.txt`

### 必需的 DLL 文件
程序需要以下 DLL 文件 (与程序放在同一目录):
- `fpengine.dll` - 指纹引擎核心库
- `fpcorex64.dll` - 指纹处理核心库
- `nbis64.dll` - NBIS 算法库

---

## 🚀 安装说明

### 方法一: 使用源码运行

1. **克隆仓库**
```bash
git clone https://github.com/yourusername/fingerprint-login.git
cd fingerprint-login
```

2. **安装依赖**
```bash
pip install -r requirements.txt
```

3. **准备 DLL 文件**
   - 将 `fpengine.dll`、`fpcorex64.dll`、`nbis64.dll` 放在项目根目录

4. **运行程序**
```bash
python Fingerprint_login.py
```

### 方法二: 使用打包的可执行文件

1. **下载发行版**
   - 从 [Releases](https://github.com/yourusername/fingerprint-login/releases) 下载最新版本

2. **解压并运行**
   - 解压文件到任意目录
   - 双击 `Fingerprint_login.exe` 运行

---

## 📖 使用指南

### 首次启动

1. **默认登录密码**: `admin`
2. 首次登录后建议立即修改密码

### 主要操作

#### 指纹注册
1. 点击左侧菜单 **"指纹注册"**
2. 输入用户姓名和选择权限等级
3. 按提示将手指放在读头上 (默认需采集 3 次)
4. 等待注册成功提示

#### 指纹识别
1. 点击左侧菜单 **"指纹识别"**
2. 将手指放在读头上
3. 系统自动匹配并显示用户信息

#### 用户管理
1. 点击左侧菜单 **"用户管理"**
2. 可以查看、搜索、编辑、删除用户
3. 编辑和删除操作需要管理员密码验证

#### 数据导出
1. 点击左侧菜单 **"数据导出"**
2. 选择是否加密导出
3. 选择保存位置

#### 数据导入
1. 点击左侧菜单 **"数据导入"**
2. 选择导入文件
3. 如果文件已加密,勾选 "文件已加密" 并输入密码
4. 选择合并或替换模式

---

## ⚙️ 配置说明

### 数据文件
- **主数据文件**: `fingerprint_data.json` (在程序目录下)
- **日志文件**: `fingerprint_system.log`
- **备份文件**: `fingerprint_data_backup_*.json`

### 权限等级说明
- **等级 1**: 最高权限
- **等级 2**: 高级权限
- **等级 3**: 普通权限
- **等级 4**: 基础权限

### 修改默认密码
首次登录后:
1. 点击右上角设置图标
2. 选择 "修改密码"
3. 输入新密码并确认

---

## 🔧 开发说明

### 项目结构
```
fingerprint-login/
├── Fingerprint_login.py    # 主程序
├── requirements.txt         # Python 依赖
├── README.md               # 说明文档
├── fpengine.dll            # 指纹引擎
├── fpcorex64.dll           # 核心处理库
├── nbis64.dll              # 算法库
├── fingerprint_data.json   # 数据文件 (运行时生成)
└── fingerprint_system.log  # 日志文件 (运行时生成)
```

### 打包为可执行文件

使用 PyInstaller 打包:

```bash
pyinstaller --onefile --windowed --icon=app.ico \
  --add-data "fpengine.dll;." \
  --add-data "fpcorex64.dll;." \
  --add-data "nbis64.dll;." \
  Fingerprint_login.py
```

### 代码架构

- **DLLLoader**: DLL 动态加载器
- **FingerprintDevice**: 指纹设备控制类
- **DataManager**: 数据管理类
- **Theme**: 界面主题配置
- **ModernButton**: 现代化按钮组件
- **LoginWindow**: 登录窗口
- **MainApplication**: 主应用程序

### 线程安全设计

所有 GUI 操作通过 `root.after()` 在主线程执行,确保界面稳定性。

---

## ❓ 常见问题

### Q1: 程序启动后提示找不到 DLL?
**A**: 确保 `fpengine.dll`、`fpcorex64.dll`、`nbis64.dll` 与程序在同一目录。

### Q2: 指纹识别准确率低?
**A**: 
- 确保手指干净、干燥
- 注册时多次采集同一手指
- 尝试重新注册指纹

### Q3: 忘记管理员密码怎么办?
**A**: 
- 删除 `fingerprint_data.json` 文件 (会清空所有数据)
- 或手动编辑文件修改密码哈希值

### Q4: 如何备份数据?
**A**: 
- 使用程序内的 "数据导出" 功能
- 或直接复制 `fingerprint_data.json` 文件

### Q5: 程序崩溃如何查看日志?
**A**: 打开 `fingerprint_system.log` 文件查看详细错误信息。

---

## 📝 更新日志

### v5.1 (当前版本)
- ✅ 修复线程安全问题
- ✅ 完善 Widget 生命周期管理
- ✅ 增强异常处理和日志记录
- ✅ 优化 DLL 加载机制
- ✅ 支持 PyInstaller 打包
- ✅ 自动清理过期备份文件
- ✅ 改进加密解密错误处理

### v5.0
- 🎨 全新现代化界面设计
- 📊 添加仪表板统计功能
- 🔐 增加数据加密功能

### v4.x
- 初始版本功能实现

---

## 📄 许可证

本项目采用 MIT 许可证 - 详见 [LICENSE](LICENSE) 文件

---

## 🤝 贡献

欢迎提交 Issue 和 Pull Request!

### 贡献指南
1. Fork 本仓库
2. 创建特性分支 (`git checkout -b feature/AmazingFeature`)
3. 提交更改 (`git commit -m 'Add some AmazingFeature'`)
4. 推送到分支 (`git push origin feature/AmazingFeature`)
5. 开启 Pull Request

---

## 📧 联系方式

如有问题或建议,请通过以下方式联系:

- 提交 [Issue](https://github.com/yourusername/fingerprint-login/issues)
- 发送邮件至: 1323412519@qq.com

---

## 🙏 致谢

- 感谢 LRU 指纹设备 SDK 提供的技术支持
- 感谢所有贡献者的付出

---

<div align="center">

**⭐ 如果这个项目对你有帮助,请给个 Star! ⭐**

Made with ❤️ by [Your Name]

</div>
