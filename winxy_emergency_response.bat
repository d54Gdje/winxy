@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ========================================
:: Windows紧急响应系统 - 主控制台
:: 版本: 1.0
:: 作者: WinXY Emergency Response Team
:: ========================================

title Windows紧急响应系统 - WinXY Emergency Response

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [错误] 需要管理员权限运行此脚本
    echo 请右键点击脚本，选择"以管理员身份运行"
    echo.
    pause
    exit /b 1
)

:: 设置颜色和样式
color 0A

:: 创建必要的目录
if not exist "logs" mkdir logs
if not exist "reports" mkdir reports
if not exist "uploads" mkdir uploads
if not exist "temp" mkdir temp

:: 设置时间戳
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "timestamp=%dt:~0,4%-%dt:~4,2%-%dt:~6,2%_%dt:~8,2%-%dt:~10,2%-%dt:~12,2%"

:main_menu
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                        Windows紧急响应系统 - WinXY                          ║
echo ║                           Emergency Response System                          ║
echo ╠══════════════════════════════════════════════════════════════════════════════╣
echo ║                                                                              ║
echo ║  [1] 快速系统扫描 - 收集基本系统信息                                        ║
echo ║  [2] 深度安全分析 - 全面安全检查                                            ║
echo ║  [3] 文档分析模块 - 上传日志文件分析                                        ║
echo ║  [4] 应急命令库 - 查看Windows应急命令                                       ║
echo ║  [5] 启动Web界面 - 图形化分析界面                                           ║
echo ║  [6] 查看历史报告 - 浏览之前的分析结果                                      ║
echo ║  [7] 系统配置 - 配置分析参数                                                ║
echo ║  [8] 帮助文档 - 使用说明和教程                                              ║
echo ║  [0] 退出系统                                                                ║
echo ║                                                                              ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 当前时间: %date% %time%
echo 系统用户: %username%
echo 权限级别: 管理员
echo.

set /p choice="请选择操作 (0-8): "

if "%choice%"=="1" goto quick_scan
if "%choice%"=="2" goto deep_analysis
if "%choice%"=="3" goto document_analysis
if "%choice%"=="4" goto emergency_commands
if "%choice%"=="5" goto start_web_interface
if "%choice%"=="6" goto view_reports
if "%choice%"=="7" goto system_config
if "%choice%"=="8" goto help_docs
if "%choice%"=="0" goto exit_system

echo.
echo [错误] 无效选择，请输入0-8之间的数字
timeout /t 2 >nul
goto main_menu

:quick_scan
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              快速系统扫描                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [信息] 正在执行快速系统扫描...
echo.

set "report_file=reports\quick_scan_%timestamp%.txt"

echo Windows紧急响应系统 - 快速扫描报告 > "%report_file%"
echo 生成时间: %date% %time% >> "%report_file%"
echo 扫描类型: 快速扫描 >> "%report_file%"
echo ======================================== >> "%report_file%"
echo. >> "%report_file%"

echo [1/8] 收集系统基本信息...
echo === 系统基本信息 === >> "%report_file%"
systeminfo | findstr /C:"OS Name" /C:"OS Version" /C:"System Type" /C:"Total Physical Memory" >> "%report_file%"
echo. >> "%report_file%"

echo [2/8] 检查当前用户信息...
echo === 当前用户信息 === >> "%report_file%"
whoami /all >> "%report_file%"
echo. >> "%report_file%"

echo [3/8] 获取网络配置...
echo === 网络配置信息 === >> "%report_file%"
ipconfig /all >> "%report_file%"
echo. >> "%report_file%"

echo [4/8] 检查活动网络连接...
echo === 活动网络连接 === >> "%report_file%"
netstat -ano | findstr "ESTABLISHED" >> "%report_file%"
echo. >> "%report_file%"

echo [5/8] 获取运行进程列表...
echo === 运行进程列表 === >> "%report_file%"
tasklist /v >> "%report_file%"
echo. >> "%report_file%"

echo [6/8] 检查系统服务...
echo === 系统服务状态 === >> "%report_file%"
sc query type= service state= all >> "%report_file%"
echo. >> "%report_file%"

echo [7/8] 检查启动项...
echo === 启动项信息 === >> "%report_file%"
wmic startup get Caption,Command,Location,User >> "%report_file%"
echo. >> "%report_file%"

echo [8/8] 检查最近登录记录...
echo === 最近登录记录 === >> "%report_file%"
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:10 /rd:true /f:text >> "%report_file%"
echo. >> "%report_file%"

echo.
echo [完成] 快速扫描已完成！
echo [报告] 扫描结果已保存到: %report_file%
echo.

echo 是否要查看扫描结果？
choice /c YN /m "按Y查看，按N返回主菜单"
if %errorlevel%==1 (
    cls
    type "%report_file%"
    echo.
    echo [信息] 报告显示完毕，按任意键返回主菜单...
    pause >nul
)
goto main_menu

:deep_analysis
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              深度安全分析                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [信息] 正在执行深度安全分析，这可能需要几分钟时间...
echo.

set "report_file=reports\deep_analysis_%timestamp%.txt"

echo Windows紧急响应系统 - 深度安全分析报告 > "%report_file%"
echo 生成时间: %date% %time% >> "%report_file%"
echo 分析类型: 深度安全分析 >> "%report_file%"
echo ======================================== >> "%report_file%"
echo. >> "%report_file%"

echo [1/15] 系统基本信息收集...
echo === 系统详细信息 === >> "%report_file%"
systeminfo >> "%report_file%"
echo. >> "%report_file%"

echo [2/15] 用户账户分析...
echo === 用户账户分析 === >> "%report_file%"
echo --- 所有用户账户 --- >> "%report_file%"
net user >> "%report_file%"
echo. >> "%report_file%"
echo --- 管理员组成员 --- >> "%report_file%"
net localgroup Administrators >> "%report_file%"
echo. >> "%report_file%"
echo --- 隐藏用户检查 --- >> "%report_file%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" 2>nul >> "%report_file%"
if %errorlevel% neq 0 echo 未发现隐藏用户配置 >> "%report_file%"
echo. >> "%report_file%"

echo [3/15] 进程详细分析...
echo === 进程详细分析 === >> "%report_file%"
echo --- 所有进程详细信息 --- >> "%report_file%"
tasklist /v >> "%report_file%"
echo. >> "%report_file%"
echo --- 进程模块信息 --- >> "%report_file%"
wmic process get Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath >> "%report_file%"
echo. >> "%report_file%"

echo [4/15] 网络连接深度分析...
echo === 网络连接深度分析 === >> "%report_file%"
echo --- 所有网络连接 --- >> "%report_file%"
netstat -ano >> "%report_file%"
echo. >> "%report_file%"
echo --- 外部连接分析 --- >> "%report_file%"
for /f "tokens=3,5" %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| findstr /v "127.0.0.1" ^| findstr /v "::1" ^| findstr /v "0.0.0.0"') do (
    echo 外部连接: %%a 进程ID: %%b >> "%report_file%"
    for /f "tokens=1" %%c in ('tasklist /fi "PID eq %%b" /fo csv /nh 2^>nul ^| findstr /v "INFO"') do (
        echo   关联进程: %%c >> "%report_file%"
    )
)
echo. >> "%report_file%"

echo [5/15] 服务安全检查...
echo === 服务安全检查 === >> "%report_file%"
sc query type= service state= all >> "%report_file%"
echo. >> "%report_file%"

echo [6/15] 启动项安全分析...
echo === 启动项安全分析 === >> "%report_file%"
wmic startup get Caption,Command,Location,User >> "%report_file%"
echo. >> "%report_file%"

echo [7/15] 注册表关键项检查...
echo === 注册表关键项检查 === >> "%report_file%"
echo --- Run键值检查 --- >> "%report_file%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%report_file%"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%report_file%"
echo. >> "%report_file%"

echo [8/15] 文件系统权限检查...
echo === 文件系统权限检查 === >> "%report_file%"
icacls C:\Windows\System32 >> "%report_file%"
echo. >> "%report_file%"

echo [9/15] 防火墙状态检查...
echo === 防火墙状态检查 === >> "%report_file%"
netsh advfirewall show allprofiles >> "%report_file%"
echo. >> "%report_file%"

echo [10/15] 安全事件日志分析...
echo === 安全事件日志分析 === >> "%report_file%"
echo --- 失败登录尝试 (Event ID 4625) --- >> "%report_file%"
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text >> "%report_file%"
echo. >> "%report_file%"
echo --- 成功登录记录 (Event ID 4624) --- >> "%report_file%"
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text >> "%report_file%"
echo. >> "%report_file%"

echo [11/15] 系统完整性检查...
echo === 系统完整性检查 === >> "%report_file%"
sfc /verifyonly >> "%report_file%"
echo. >> "%report_file%"

echo [12/15] 磁盘使用情况...
echo === 磁盘使用情况 === >> "%report_file%"
wmic logicaldisk get Size,FreeSpace,Caption >> "%report_file%"
echo. >> "%report_file%"

echo [13/15] 内存使用分析...
echo === 内存使用分析 === >> "%report_file%"
wmic OS get TotalVisibleMemorySize,FreePhysicalMemory >> "%report_file%"
echo. >> "%report_file%"

echo [14/15] 网络配置详细信息...
echo === 网络配置详细信息 === >> "%report_file%"
ipconfig /all >> "%report_file%"
echo. >> "%report_file%"

echo [15/15] 生成安全评估摘要...
echo === 安全评估摘要 === >> "%report_file%"
echo 分析完成时间: %date% %time% >> "%report_file%"

:: 简单的威胁评估
set threat_level=低
set threat_count=0

:: 检查外部连接数量
for /f %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| findstr /v "127.0.0.1" ^| findstr /v "::1" ^| find /c /v ""') do set external_connections=%%a
if %external_connections% gtr 10 (
    set threat_level=中
    set /a threat_count+=1
)

:: 检查管理员用户数量
for /f %%a in ('net localgroup Administrators ^| find /c /v ""') do set admin_count=%%a
if %admin_count% gtr 5 (
    set threat_level=高
    set /a threat_count+=1
)

echo. >> "%report_file%"
echo 威胁等级: %threat_level% >> "%report_file%"
echo 发现问题数量: %threat_count% >> "%report_file%"
echo 外部连接数量: %external_connections% >> "%report_file%"
echo 管理员用户数量: %admin_count% >> "%report_file%"
echo. >> "%report_file%"

echo 建议措施: >> "%report_file%"
if %external_connections% gtr 10 echo - 检查异常外部网络连接 >> "%report_file%"
if %admin_count% gtr 5 echo - 审查管理员账户的必要性 >> "%report_file%"
echo - 定期更新系统补丁 >> "%report_file%"
echo - 启用Windows Defender实时保护 >> "%report_file%"
echo - 配置强密码策略 >> "%report_file%"

echo.
echo [完成] 深度安全分析已完成！
echo [报告] 分析结果已保存到: %report_file%
echo [威胁] 当前威胁等级: %threat_level%
echo.

echo 是否要查看分析结果？
choice /c YN /m "按Y查看，按N返回主菜单"
if %errorlevel%==1 (
    cls
    type "%report_file%"
    echo.
    echo [信息] 报告显示完毕，按任意键返回主菜单...
    pause >nul
)
goto main_menu

:document_analysis
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              文档分析模块                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [信息] 文档分析模块可以分析以下类型的文件：
echo   - .txt 文本文件
echo   - .log 日志文件  
echo   - .csv 逗号分隔值文件
echo   - .json JSON格式文件
echo.
echo [1] 分析单个文件
echo [2] 批量分析文件夹中的文件
echo [3] 启动Web界面进行拖拽上传
echo [0] 返回主菜单
echo.

set /p doc_choice="请选择操作 (0-3): "

if "%doc_choice%"=="1" goto analyze_single_file
if "%doc_choice%"=="2" goto analyze_folder
if "%doc_choice%"=="3" goto start_web_interface
if "%doc_choice%"=="0" goto main_menu

echo.
echo [错误] 无效选择
timeout /t 2 >nul
goto document_analysis

:analyze_single_file
echo.
set /p file_path="请输入要分析的文件完整路径: "

if not exist "%file_path%" (
    echo [错误] 文件不存在: %file_path%
    pause
    goto document_analysis
)

echo.
echo [信息] 正在分析文件: %file_path%
echo.

set "analysis_report=reports\file_analysis_%timestamp%.txt"

echo 文件分析报告 > "%analysis_report%"
echo 分析时间: %date% %time% >> "%analysis_report%"
echo 源文件: %file_path% >> "%analysis_report%"
echo ======================================== >> "%analysis_report%"
echo. >> "%analysis_report%"

:: 文件基本信息
echo === 文件基本信息 === >> "%analysis_report%"
dir "%file_path%" >> "%analysis_report%"
echo. >> "%analysis_report%"

:: 分析文件内容
echo === 内容分析 === >> "%analysis_report%"

:: 检查IP地址
echo --- 发现的IP地址 --- >> "%analysis_report%"
findstr /R "\<[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\>" "%file_path%" >> "%analysis_report%"
echo. >> "%analysis_report%"

:: 检查进程信息
echo --- 进程相关信息 --- >> "%analysis_report%"
findstr /I "process\|pid\|exe\|dll" "%file_path%" >> "%analysis_report%"
echo. >> "%analysis_report%"

:: 检查用户信息
echo --- 用户相关信息 --- >> "%analysis_report%"
findstr /I "user\|admin\|login\|logon" "%file_path%" >> "%analysis_report%"
echo. >> "%analysis_report%"

:: 检查错误和警告
echo --- 错误和警告信息 --- >> "%analysis_report%"
findstr /I "error\|warning\|fail\|denied\|attack" "%file_path%" >> "%analysis_report%"
echo. >> "%analysis_report%"

echo [完成] 文件分析完成！
echo [报告] 分析结果已保存到: %analysis_report%
echo.

echo 是否要查看分析结果？
choice /c YN /m "按Y查看，按N返回"
if %errorlevel%==1 (
    cls
    type "%analysis_report%"
    echo.
    echo [信息] 报告显示完毕，按任意键继续...
    pause >nul
)
goto document_analysis

:analyze_folder
echo.
set /p folder_path="请输入要分析的文件夹路径: "

if not exist "%folder_path%" (
    echo [错误] 文件夹不存在: %folder_path%
    pause
    goto document_analysis
)

echo.
echo [信息] 正在批量分析文件夹: %folder_path%
echo.

set "batch_report=reports\batch_analysis_%timestamp%.txt"

echo 批量文件分析报告 > "%batch_report%"
echo 分析时间: %date% %time% >> "%batch_report%"
echo 源文件夹: %folder_path% >> "%batch_report%"
echo ======================================== >> "%batch_report%"
echo. >> "%batch_report%"

set file_count=0
for %%f in ("%folder_path%\*.txt" "%folder_path%\*.log" "%folder_path%\*.csv") do (
    if exist "%%f" (
        set /a file_count+=1
        echo [!file_count!] 分析文件: %%f
        echo === 文件: %%f === >> "%batch_report%"
        
        :: 基本信息
        dir "%%f" | findstr /V "Directory" >> "%batch_report%"
        
        :: IP地址检查
        echo IP地址: >> "%batch_report%"
        findstr /R "\<[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\.[0-9][0-9]*\>" "%%f" | find /c /v "" >> "%batch_report%"
        
        :: 进程检查
        echo 进程信息: >> "%batch_report%"
        findstr /I "process\|pid" "%%f" | find /c /v "" >> "%batch_report%"
        
        echo. >> "%batch_report%"
    )
)

echo.
echo [完成] 批量分析完成！共分析 %file_count% 个文件
echo [报告] 分析结果已保存到: %batch_report%
echo.

echo 是否要查看分析结果？
choice /c YN /m "按Y查看，按N返回"
if %errorlevel%==1 (
    cls
    type "%batch_report%"
    echo.
    echo [信息] 报告显示完毕，按任意键继续...
    pause >nul
)
goto document_analysis

:emergency_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            Windows应急命令库                                ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [1] 系统信息收集命令
echo [2] 进程管理命令
echo [3] 网络诊断命令
echo [4] 文件操作命令
echo [5] 安全管理命令
echo [6] 服务管理命令
echo [7] 注册表操作命令
echo [8] 事件日志命令
echo [9] 性能监控命令
echo [0] 返回主菜单
echo.

set /p cmd_choice="请选择命令类别 (0-9): "

if "%cmd_choice%"=="1" goto system_info_commands
if "%cmd_choice%"=="2" goto process_commands
if "%cmd_choice%"=="3" goto network_commands
if "%cmd_choice%"=="4" goto file_commands
if "%cmd_choice%"=="5" goto security_commands
if "%cmd_choice%"=="6" goto service_commands
if "%cmd_choice%"=="7" goto registry_commands
if "%cmd_choice%"=="8" goto event_commands
if "%cmd_choice%"=="9" goto performance_commands
if "%cmd_choice%"=="0" goto main_menu

echo.
echo [错误] 无效选择
timeout /t 2 >nul
goto emergency_commands

:system_info_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            系统信息收集命令                                 ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. systeminfo - 显示详细系统信息
echo    用途: 获取操作系统版本、硬件配置、补丁信息
echo    示例: systeminfo
echo    输出: 系统名称、版本、内存、处理器等详细信息
echo.
echo 2. hostname - 显示计算机名
echo    用途: 快速获取主机名
echo    示例: hostname
echo    输出: 当前计算机名称
echo.
echo 3. ver - 显示Windows版本
echo    用途: 快速查看系统版本
echo    示例: ver
echo    输出: Microsoft Windows版本信息
echo.
echo 4. whoami - 显示当前用户信息
echo    用途: 查看当前登录用户和权限
echo    示例: whoami /all
echo    输出: 用户名、组成员身份、权限等
echo.
echo 5. ipconfig - 网络配置信息
echo    用途: 查看网络接口配置
echo    示例: ipconfig /all
echo    输出: IP地址、子网掩码、网关、DNS等
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:process_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              进程管理命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. tasklist - 显示运行中的进程
echo    用途: 查看所有运行进程的详细信息
echo    示例: tasklist /v
echo    输出: 进程名、PID、内存使用、用户等
echo.
echo 2. taskkill - 终止进程
echo    用途: 强制结束指定进程
echo    示例: taskkill /PID 1234 /F
echo    注意: /F参数强制终止，谨慎使用
echo.
echo 3. wmic process - 进程详细信息
echo    用途: 获取进程的完整路径和命令行
echo    示例: wmic process get Name,ProcessId,CommandLine
echo    输出: 进程名、ID、启动命令行
echo.
echo 4. 查找特定进程
echo    用途: 搜索包含特定名称的进程
echo    示例: tasklist | findstr "notepad"
echo    输出: 包含notepad的所有进程
echo.
echo 5. 按内存使用排序
echo    用途: 查看内存使用最多的进程
echo    示例: tasklist /fo table | sort /r /+5
echo    输出: 按内存使用量降序排列的进程
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:network_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              网络诊断命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. netstat - 网络连接状态
echo    用途: 查看网络连接、监听端口、路由表
echo    示例: netstat -ano
echo    输出: 协议、本地地址、外部地址、状态、PID
echo.
echo 2. ping - 网络连通性测试
echo    用途: 测试到目标主机的网络连接
echo    示例: ping -t 8.8.8.8
echo    输出: 延迟时间、丢包率等
echo.
echo 3. tracert - 路由跟踪
echo    用途: 显示数据包到达目标的路径
echo    示例: tracert google.com
echo    输出: 经过的每个路由器和延迟
echo.
echo 4. nslookup - DNS查询
echo    用途: 查询域名解析信息
echo    示例: nslookup google.com
echo    输出: IP地址和DNS服务器信息
echo.
echo 5. arp - ARP表查看
echo    用途: 查看ARP缓存表
echo    示例: arp -a
echo    输出: IP地址和MAC地址对应关系
echo.
echo 6. 查看外部连接
echo    用途: 只显示外部网络连接
echo    示例: netstat -ano | findstr "ESTABLISHED" | findstr /v "127.0.0.1"
echo    输出: 所有活动的外部连接
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:file_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              文件操作命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. dir - 列出目录内容
echo    用途: 查看文件和文件夹
echo    示例: dir /a /s C:\Windows\System32\*.exe
echo    输出: 文件名、大小、修改时间等
echo.
echo 2. copy - 复制文件
echo    用途: 复制文件到指定位置
echo    示例: copy C:\source\file.txt D:\backup\
echo    注意: 目标路径必须存在
echo.
echo 3. del - 删除文件
echo    用途: 删除指定文件
echo    示例: del /f /q C:\temp\*.tmp
echo    注意: /f强制删除，/q安静模式
echo.
echo 4. mkdir - 创建目录
echo    用途: 创建新文件夹
echo    示例: mkdir C:\backup\logs
echo    输出: 创建指定路径的文件夹
echo.
echo 5. attrib - 文件属性
echo    用途: 查看或修改文件属性
echo    示例: attrib +h +s file.txt
echo    输出: 设置隐藏和系统属性
echo.
echo 6. findstr - 文件内容搜索
echo    用途: 在文件中搜索特定文本
echo    示例: findstr /i "error" C:\logs\*.log
echo    输出: 包含"error"的所有行
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:security_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              安全管理命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. net user - 用户账户管理
echo    用途: 查看和管理用户账户
echo    示例: net user
echo    输出: 所有用户账户列表
echo.
echo 2. net localgroup - 本地组管理
echo    用途: 查看和管理本地用户组
echo    示例: net localgroup Administrators
echo    输出: 管理员组成员列表
echo.
echo 3. icacls - 文件权限管理
echo    用途: 查看和修改文件/文件夹权限
echo    示例: icacls C:\Windows\System32
echo    输出: 详细的权限设置
echo.
echo 4. takeown - 获取文件所有权
echo    用途: 获取文件或文件夹的所有权
echo    示例: takeown /f C:\file.txt
echo    注意: 需要管理员权限
echo.
echo 5. whoami /priv - 查看当前权限
echo    用途: 显示当前用户的所有权限
echo    示例: whoami /priv
echo    输出: 权限名称和状态
echo.
echo 6. gpresult - 组策略结果
echo    用途: 显示应用的组策略
echo    示例: gpresult /r
echo    输出: 当前应用的策略设置
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:service_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              服务管理命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. sc query - 查询服务状态
echo    用途: 查看系统服务状态
echo    示例: sc query type= service state= all
echo    输出: 服务名称、状态、类型等
echo.
echo 2. net start/stop - 启动/停止服务
echo    用途: 控制服务的启动和停止
echo    示例: net start "Windows Defender"
echo    注意: 服务名称要准确
echo.
echo 3. sc config - 配置服务
echo    用途: 修改服务配置
echo    示例: sc config ServiceName start= disabled
echo    注意: 等号后面要有空格
echo.
echo 4. wmic service - 服务详细信息
echo    用途: 获取服务的详细信息
echo    示例: wmic service get Name,State,StartMode
echo    输出: 服务名、状态、启动模式
echo.
echo 5. tasklist /svc - 服务进程映射
echo    用途: 查看服务对应的进程
echo    示例: tasklist /svc
echo    输出: 进程和托管的服务
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:registry_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              注册表操作命令                                 ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. reg query - 查询注册表
echo    用途: 读取注册表键值
echo    示例: reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
echo    输出: 指定键下的所有值
echo.
echo 2. reg add - 添加注册表项
echo    用途: 创建新的注册表键或值
echo    示例: reg add "HKCU\Software\Test" /v TestValue /t REG_SZ /d "TestData"
echo    注意: 需要指定类型和数据
echo.
echo 3. reg delete - 删除注册表项
echo    用途: 删除注册表键或值
echo    示例: reg delete "HKCU\Software\Test" /v TestValue /f
echo    注意: /f参数强制删除，谨慎使用
echo.
echo 4. 常用启动项检查
echo    用途: 检查系统启动项
echo    位置: HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
echo    位置: HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run
echo.
echo 5. 隐藏用户检查
echo    用途: 检查隐藏的用户账户
echo    位置: HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList
echo.
echo ⚠️  警告: 注册表操作有风险，建议先备份！
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:event_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              事件日志命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. wevtutil qe - 查询事件日志
echo    用途: 查询Windows事件日志
echo    示例: wevtutil qe Security /c:10 /rd:true /f:text
echo    输出: 最新的10条安全日志
echo.
echo 2. 登录失败事件 (Event ID 4625)
echo    用途: 查看失败的登录尝试
echo    示例: wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text
echo    输出: 登录失败的详细信息
echo.
echo 3. 成功登录事件 (Event ID 4624)
echo    用途: 查看成功的登录记录
echo    示例: wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text
echo    输出: 成功登录的详细信息
echo.
echo 4. 系统启动事件 (Event ID 6005)
echo    用途: 查看系统启动记录
echo    示例: wevtutil qe System /q:"*[System[(EventID=6005)]]" /c:10 /rd:true /f:text
echo    输出: 系统启动时间记录
echo.
echo 5. 应用程序错误事件
echo    用途: 查看应用程序错误
echo    示例: wevtutil qe Application /q:"*[System[(Level=2)]]" /c:20 /rd:true /f:text
echo    输出: 应用程序错误详情
echo.
echo 6. eventvwr - 图形化事件查看器
echo    用途: 打开Windows事件查看器
echo    示例: eventvwr
echo    输出: 图形化的事件日志界面
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:performance_commands
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              性能监控命令                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 1. perfmon - 性能监视器
echo    用途: 打开Windows性能监视器
echo    示例: perfmon
echo    输出: 图形化性能监控界面
echo.
echo 2. resmon - 资源监视器
echo    用途: 打开资源监视器
echo    示例: resmon
echo    输出: 详细的系统资源使用情况
echo.
echo 3. wmic cpu - CPU信息
echo    用途: 获取CPU详细信息
echo    示例: wmic cpu get Name,NumberOfCores,LoadPercentage
echo    输出: CPU型号、核心数、使用率
echo.
echo 4. wmic memorychip - 内存信息
echo    用途: 获取内存条详细信息
echo    示例: wmic memorychip get Capacity,Speed,Manufacturer
echo    输出: 内存容量、频率、制造商
echo.
echo 5. wmic logicaldisk - 磁盘信息
echo    用途: 获取磁盘使用情况
echo    示例: wmic logicaldisk get Size,FreeSpace,Caption
echo    输出: 磁盘总容量、可用空间
echo.
echo 6. typeperf - 性能计数器
echo    用途: 实时监控性能计数器
echo    示例: typeperf "\Processor(_Total)\% Processor Time" -sc 10
echo    输出: CPU使用率实时数据
echo.
echo 按任意键返回命令库主菜单...
pause >nul
goto emergency_commands

:start_web_interface
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              启动Web界面                                    ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [信息] 正在启动Web分析界面...
echo.

:: 检查Python是否安装
python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [错误] 未检测到Python，正在尝试安装...
    echo [信息] 请手动安装Python 3.7或更高版本
    echo [信息] 下载地址: https://www.python.org/downloads/
    pause
    goto main_menu
)

:: 检查必要的Python包
echo [信息] 检查Python依赖包...
python -c "import flask" >nul 2>&1
if %errorlevel% neq 0 (
    echo [信息] 正在安装Flask...
    pip install flask flask-cors
)

:: 启动Web服务器
echo [信息] 启动Web服务器...
echo [信息] Web界面将在浏览器中打开
echo [信息] 地址: http://localhost:12000
echo.
echo [提示] 按Ctrl+C停止服务器
echo.

start http://localhost:12000
python winxy_web_server.py

echo.
echo [信息] Web服务器已停止
pause
goto main_menu

:view_reports
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              历史报告查看                                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

if not exist "reports\*.*" (
    echo [信息] 暂无历史报告
    echo.
    pause
    goto main_menu
)

echo [信息] 可用的历史报告：
echo.
set report_count=0
for %%f in (reports\*.txt) do (
    set /a report_count+=1
    echo [!report_count!] %%f
)

echo.
echo [0] 返回主菜单
echo.

set /p report_choice="请选择要查看的报告编号 (0-%report_count%): "

if "%report_choice%"=="0" goto main_menu

set current_count=0
for %%f in (reports\*.txt) do (
    set /a current_count+=1
    if !current_count!==!report_choice! (
        cls
        echo 正在显示报告: %%f
        echo ========================================
        type "%%f"
        echo.
        echo ========================================
        echo 报告显示完毕，按任意键返回...
        pause >nul
        goto view_reports
    )
)

echo [错误] 无效的报告编号
timeout /t 2 >nul
goto view_reports

:system_config
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              系统配置                                       ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo [1] 查看当前配置
echo [2] 设置报告保存路径
echo [3] 设置日志级别
echo [4] 清理临时文件
echo [5] 重置所有配置
echo [0] 返回主菜单
echo.

set /p config_choice="请选择配置选项 (0-5): "

if "%config_choice%"=="1" goto view_config
if "%config_choice%"=="2" goto set_report_path
if "%config_choice%"=="3" goto set_log_level
if "%config_choice%"=="4" goto cleanup_temp
if "%config_choice%"=="5" goto reset_config
if "%config_choice%"=="0" goto main_menu

echo [错误] 无效选择
timeout /t 2 >nul
goto system_config

:view_config
echo.
echo === 当前系统配置 ===
echo 报告保存路径: %cd%\reports
echo 日志保存路径: %cd%\logs
echo 临时文件路径: %cd%\temp
echo 上传文件路径: %cd%\uploads
echo 当前用户: %username%
echo 系统时间: %date% %time%
echo.
pause
goto system_config

:cleanup_temp
echo.
echo [信息] 正在清理临时文件...
if exist "temp\*.*" del /q "temp\*.*"
if exist "uploads\*.*" del /q "uploads\*.*"
echo [完成] 临时文件清理完成
pause
goto system_config

:help_docs
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              帮助文档                                       ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo === Windows紧急响应系统使用指南 ===
echo.
echo 1. 快速系统扫描
echo    - 执行基本的系统信息收集
echo    - 适用于快速了解系统状态
echo    - 生成简要的安全报告
echo.
echo 2. 深度安全分析
echo    - 全面的系统安全检查
echo    - 包含用户、进程、网络、服务等分析
echo    - 提供威胁等级评估和建议
echo.
echo 3. 文档分析模块
echo    - 支持.txt、.log、.csv、.json文件
echo    - 自动检测IP地址、进程、用户信息
echo    - 支持单文件和批量分析
echo.
echo 4. 应急命令库
echo    - 提供Windows应急响应常用命令
echo    - 包含详细的使用说明和示例
echo    - 按功能分类便于查找
echo.
echo 5. Web界面
echo    - 提供图形化的分析界面
echo    - 支持拖拽上传文件
echo    - 实时显示分析结果
echo.
echo === 注意事项 ===
echo - 建议以管理员权限运行
echo - 定期清理临时文件
echo - 保护好生成的报告文件
echo - 在生产环境使用前先测试
echo.
echo 按任意键返回主菜单...
pause >nul
goto main_menu

:exit_system
cls
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              退出系统                                       ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 感谢使用Windows紧急响应系统！
echo.
echo 系统信息：
echo - 本次会话开始时间: %timestamp%
echo - 当前时间: %date% %time%
echo - 报告保存位置: %cd%\reports
echo.
echo 如有问题或建议，请联系技术支持。
echo.
echo 按任意键退出...
pause >nul
exit /b 0

:: 错误处理
:error_handler
echo.
echo [错误] 发生未知错误，错误代码: %errorlevel%
echo [信息] 请检查系统权限和网络连接
echo.
pause
goto main_menu