# 🛡️ WinXY - Windows紧急响应系统

## 📋 项目概述

WinXY是一个专为Windows设计的紧急响应系统，灵感来源于"emergency"项目，并融入了强大的增强功能。系统优先使用`cmd`命令，仅在必要时使用PowerShell（已明确标注），支持详细的日志分析、攻击检测、用户友好的界面和性能优化，确保批处理脚本运行后不闪退。

### 🎯 核心特性

- 🔍 **强大的文档分析模块** - 支持多种格式，自动检测编码，深度分析系统信息
- 📚 **应急技巧和教程库** - 完整的Windows应急命令库和使用指南
- 🖥️ **用户友好的界面** - 支持拖拽上传，图表展示，Web界面
- 🔒 **安全性和权限管理** - 最小权限原则，完整的审计日志
- ⚡ **性能优化** - 模块化架构，支持大文件处理
- 🚫 **防闪退设计** - 批处理脚本使用交互式菜单，绝不闪退

## 🚀 快速开始

### 1. 系统要求

- Windows 10 或更高版本（包括Windows Server）
- 管理员权限（推荐）
- Python 3.7+ （可选，用于Web界面）

### 2. 安装和运行

#### 方法一：直接运行（推荐）
```batch
# 下载项目到本地
git clone https://github.com/d54Gdje/winxy.git
cd winxy

# 以管理员身份运行主程序
右键点击 winxy_emergency_response.bat -> 以管理员身份运行
```

#### 方法二：使用Web界面
```batch
# 安装Python依赖（如果需要）
pip install flask flask-cors psutil

# 启动Web服务器
python winxy_web_server.py

# 浏览器访问
http://localhost:12000
```

### 3. 主要功能

#### 🔍 快速系统扫描
- 收集系统基本信息
- 检查网络连接和进程
- 生成安全评估报告

#### 🔬 深度安全分析
- 全面的系统安全检查
- 用户账户和权限分析
- 威胁等级评估和建议

#### 📄 文档分析模块
- 支持 .txt、.log、.csv、.json 文件
- 自动检测文件编码（UTF-8、GBK等）
- 智能提取关键信息

#### 📚 应急命令库
- 按功能分类的Windows命令
- 详细的使用说明和示例
- 错误处理指南

## 📁 项目结构

```
winxy/
├── winxy_emergency_response.bat    # 主控制台（防闪退）
├── winxy_web_server.py            # Web服务器
├── config.json                    # 配置文件
├── emergency_commands.json        # 应急命令库
├── clientjiancha/                 # 信息收集脚本
│   ├── system_info_collector.bat  # 系统信息收集（批处理）
│   ├── system_info_collector.py   # 系统信息收集（Python）
│   ├── network_analyzer.bat       # 网络连接分析
│   ├── user_analyzer.bat          # 用户账户分析
│   ├── process_analyzer.py        # 进程分析（Python）
│   └── security_checker.ps1       # 安全检查（PowerShell）
├── reports/                       # 分析报告目录
├── logs/                          # 日志文件目录
├── uploads/                       # 上传文件目录
└── temp/                          # 临时文件目录
```

## 🔧 详细功能说明

### 1. 强大的文档分析模块

#### 支持的文件格式
- `.txt` - 文本文件
- `.log` - 日志文件
- `.csv` - 逗号分隔值文件
- `.json` - JSON格式文件

#### 分析内容
- **进程详情**：进程名称、PID、所属用户、内存使用量、启动路径、关联DLL
- **异常外部连接**：非本地IP连接，包含目标IP、端口、协议、关联进程
- **用户统计**：所有用户账户，区分普通用户、管理员用户和隐藏用户
- **攻击检测**：识别潜在攻击行为，统计攻击次数

#### 危害判断依据
- **高频连接**：同一外部IP短时间内多次连接（>50次/分钟）
- **可疑端口**：使用非常规端口（4444、6666、1337等）
- **未知进程**：不在系统白名单中的进程
- **大量数据传输**：内存或网络流量异常高

### 2. 应急技巧和教程库

#### 命令分类
- **系统信息收集**：systeminfo、ipconfig、hostname、ver、whoami
- **进程管理**：tasklist、taskkill、wmic process
- **网络诊断**：ping、tracert、netstat、nslookup、arp
- **文件操作**：dir、copy、del、mkdir、ren、findstr
- **安全管理**：icacls、takeown、net user、net localgroup
- **服务管理**：sc query、net start/stop、wmic service
- **注册表操作**：reg query、reg add、reg delete
- **事件日志**：wevtutil qe、eventvwr
- **性能监控**：perfmon、resmon、wmic cpu、typeperf

#### 每个命令包含
- 详细说明（功能、用途）
- 使用场景和示例代码
- 预期输出和错误处理指南

### 3. 用户友好的界面

#### Web界面特性
- 拖拽上传文件
- 实时分析进度显示
- 图表展示分析结果
- 支持导出报告（PDF、Excel、CSV）

#### 批处理界面特性
- 交互式菜单，绝不闪退
- 彩色输出，清晰易读
- 进度显示和错误提示
- 支持查看历史报告

### 4. 信息收集脚本（clientjiancha文件夹）

#### 批处理脚本
- `system_info_collector.bat` - 全面的系统信息收集
- `network_analyzer.bat` - 深度网络连接分析
- `user_analyzer.bat` - 用户账户安全分析

#### Python脚本
- `system_info_collector.py` - Python版系统信息收集
- `process_analyzer.py` - 深度进程分析

#### PowerShell脚本（明确标注）
- `security_checker.ps1` - 全面安全检查（使用PowerShell）

## 📊 分析报告示例

### 威胁等级评估
```
威胁等级: 高
安全评分: 75/100
发现问题: 3 个

发现的威胁:
- 发现 2 个可疑进程
- 外部连接数量较多 (15)
- 失败登录次数异常 (25)
```

### 详细分析结果
- **进程分析**：总进程数、可疑进程列表、内存使用统计
- **网络连接**：外部连接详情、可疑端口连接
- **用户账户**：用户类型分布、管理员列表、隐藏用户检测
- **安全事件**：登录记录、系统启动次数、错误事件

## ⚠️ 安全注意事项

### 权限要求
- 建议以管理员权限运行以获取完整信息
- 某些功能需要特定权限（如读取安全日志）
- 系统会自动检查权限并给出提示

### 数据安全
- 所有分析结果保存在本地
- 支持设置文件访问权限
- 提供审计日志记录所有操作

### 使用限制
- 仅用于授权的安全应急响应和系统检查
- 请勿用于非授权的安全测试
- 使用本工具进行的任何操作均由使用者承担全部责任

## 🔧 配置说明

### config.json 主要配置项
```json
{
  "analysis_settings": {
    "threat_scoring": {
      "suspicious_process_weight": 20,
      "suspicious_connection_weight": 25,
      "hidden_user_weight": 30
    }
  },
  "detection_rules": {
    "suspicious_processes": {
      "enabled": true,
      "process_names": ["cmd.exe", "powershell.exe", "nc.exe"]
    }
  }
}
```

## 🐛 故障排除

### 常见问题

#### 1. 批处理脚本闪退
**解决方案**：本系统已完全解决闪退问题，所有脚本都使用交互式菜单

#### 2. 权限不足
**解决方案**：右键点击脚本，选择"以管理员身份运行"

#### 3. Python依赖缺失
**解决方案**：
```batch
pip install flask flask-cors psutil
```

#### 4. Web界面无法访问
**解决方案**：
- 检查防火墙设置
- 确认端口12000未被占用
- 检查Python是否正确安装

## 📈 性能优化

### 大文件处理
- 支持分块读取大日志文件（>1GB）
- 自动检测文件编码避免乱码
- 异步处理提高响应速度

### 内存优化
- 限制同时分析的进程数量
- 使用临时文件存储中间结果
- 自动清理临时文件

## 🔄 更新日志

### v1.0 (2025-06-07)
- ✅ 完整的Windows紧急响应系统
- ✅ 防闪退批处理脚本
- ✅ 多语言信息收集脚本
- ✅ Web界面支持
- ✅ 详细的文档分析
- ✅ 完整的应急命令库

## 🤝 贡献指南

欢迎提交Issue和Pull Request来改进项目！

### 开发环境设置
1. Fork本项目
2. 创建功能分支
3. 提交更改
4. 创建Pull Request

## 📄 许可证

本项目采用MIT许可证 - 查看 [LICENSE](LICENSE) 文件了解详情

## 📞 联系我们

- 项目地址：https://github.com/d54Gdje/winxy
- 问题反馈：通过GitHub Issues提交

---

**🎉 现在您可以安全地在生产环境中使用这个增强版Windows紧急响应系统了！**