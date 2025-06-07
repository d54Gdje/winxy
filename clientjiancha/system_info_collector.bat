@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ========================================
:: Windows系统信息收集脚本 (批处理版本)
:: 版本: 1.0
:: 用途: 收集详细的Windows系统信息
:: ========================================

title Windows系统信息收集器 - 批处理版本

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] 建议以管理员权限运行以获取完整信息
    echo 继续以当前权限运行...
    timeout /t 3 >nul
)

:: 设置输出文件
for /f "tokens=2 delims==" %%a in ('wmic OS Get localdatetime /value') do set "dt=%%a"
set "timestamp=%dt:~0,4%-%dt:~4,2%-%dt:~6,2%_%dt:~8,2%-%dt:~10,2%-%dt:~12,2%"
set "output_file=system_info_%timestamp%.txt"

echo ========================================
echo Windows系统信息收集器
echo ========================================
echo 开始时间: %date% %time%
echo 输出文件: %output_file%
echo ========================================
echo.

echo Windows系统信息收集报告 > "%output_file%"
echo 收集时间: %date% %time% >> "%output_file%"
echo 收集工具: 批处理脚本 >> "%output_file%"
echo ======================================== >> "%output_file%"
echo. >> "%output_file%"

echo [1/20] 收集系统基本信息...
echo === 系统基本信息 === >> "%output_file%"
systeminfo >> "%output_file%"
echo. >> "%output_file%"

echo [2/20] 收集硬件信息...
echo === 硬件信息 === >> "%output_file%"
echo --- CPU信息 --- >> "%output_file%"
wmic cpu get Name,NumberOfCores,NumberOfLogicalProcessors,MaxClockSpeed >> "%output_file%"
echo. >> "%output_file%"
echo --- 内存信息 --- >> "%output_file%"
wmic memorychip get Capacity,Speed,Manufacturer,PartNumber >> "%output_file%"
echo. >> "%output_file%"
echo --- 磁盘信息 --- >> "%output_file%"
wmic diskdrive get Model,Size,InterfaceType >> "%output_file%"
echo. >> "%output_file%"

echo [3/20] 收集网络配置...
echo === 网络配置 === >> "%output_file%"
ipconfig /all >> "%output_file%"
echo. >> "%output_file%"

echo [4/20] 收集网络连接...
echo === 网络连接 === >> "%output_file%"
netstat -ano >> "%output_file%"
echo. >> "%output_file%"

echo [5/20] 收集路由表...
echo === 路由表 === >> "%output_file%"
route print >> "%output_file%"
echo. >> "%output_file%"

echo [6/20] 收集ARP表...
echo === ARP表 === >> "%output_file%"
arp -a >> "%output_file%"
echo. >> "%output_file%"

echo [7/20] 收集进程信息...
echo === 进程信息 === >> "%output_file%"
tasklist /v >> "%output_file%"
echo. >> "%output_file%"

echo [8/20] 收集详细进程信息...
echo === 详细进程信息 === >> "%output_file%"
wmic process get Name,ProcessId,ParentProcessId,CommandLine,ExecutablePath >> "%output_file%"
echo. >> "%output_file%"

echo [9/20] 收集服务信息...
echo === 服务信息 === >> "%output_file%"
sc query type= service state= all >> "%output_file%"
echo. >> "%output_file%"

echo [10/20] 收集启动项...
echo === 启动项 === >> "%output_file%"
wmic startup get Caption,Command,Location,User >> "%output_file%"
echo. >> "%output_file%"

echo [11/20] 收集用户信息...
echo === 用户信息 === >> "%output_file%"
echo --- 所有用户 --- >> "%output_file%"
net user >> "%output_file%"
echo. >> "%output_file%"
echo --- 管理员组 --- >> "%output_file%"
net localgroup Administrators >> "%output_file%"
echo. >> "%output_file%"
echo --- 当前用户权限 --- >> "%output_file%"
whoami /all >> "%output_file%"
echo. >> "%output_file%"

echo [12/20] 检查隐藏用户...
echo === 隐藏用户检查 === >> "%output_file%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo 未发现隐藏用户配置 >> "%output_file%"
echo. >> "%output_file%"

echo [13/20] 收集注册表启动项...
echo === 注册表启动项 === >> "%output_file%"
echo --- HKLM Run --- >> "%output_file%"
reg query "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%output_file%"
echo. >> "%output_file%"
echo --- HKCU Run --- >> "%output_file%"
reg query "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" >> "%output_file%"
echo. >> "%output_file%"

echo [14/20] 收集安装的软件...
echo === 安装的软件 === >> "%output_file%"
wmic product get Name,Version,Vendor >> "%output_file%"
echo. >> "%output_file%"

echo [15/20] 收集共享资源...
echo === 共享资源 === >> "%output_file%"
net share >> "%output_file%"
echo. >> "%output_file%"

echo [16/20] 收集防火墙状态...
echo === 防火墙状态 === >> "%output_file%"
netsh advfirewall show allprofiles >> "%output_file%"
echo. >> "%output_file%"

echo [17/20] 收集计划任务...
echo === 计划任务 === >> "%output_file%"
schtasks /query /fo LIST /v >> "%output_file%"
echo. >> "%output_file%"

echo [18/20] 收集环境变量...
echo === 环境变量 === >> "%output_file%"
set >> "%output_file%"
echo. >> "%output_file%"

echo [19/20] 收集系统日志摘要...
echo === 系统日志摘要 === >> "%output_file%"
echo --- 最近系统错误 --- >> "%output_file%"
wevtutil qe System /q:"*[System[(Level=2)]]" /c:10 /rd:true /f:text >> "%output_file%"
echo. >> "%output_file%"
echo --- 最近安全事件 --- >> "%output_file%"
wevtutil qe Security /q:"*[System[(EventID=4625 or EventID=4624)]]" /c:20 /rd:true /f:text >> "%output_file%"
echo. >> "%output_file%"

echo [20/20] 生成收集摘要...
echo === 收集摘要 === >> "%output_file%"
echo 收集完成时间: %date% %time% >> "%output_file%"
echo 输出文件大小: >> "%output_file%"
dir "%output_file%" | findstr "%output_file%" >> "%output_file%"
echo. >> "%output_file%"

:: 统计信息
for /f %%a in ('tasklist ^| find /c /v ""') do set process_count=%%a
for /f %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| find /c /v ""') do set connection_count=%%a
for /f %%a in ('net user ^| find /c /v ""') do set user_count=%%a

echo 统计信息: >> "%output_file%"
echo - 运行进程数: %process_count% >> "%output_file%"
echo - 网络连接数: %connection_count% >> "%output_file%"
echo - 用户账户数: %user_count% >> "%output_file%"
echo. >> "%output_file%"

echo.
echo ========================================
echo 信息收集完成！
echo ========================================
echo 输出文件: %output_file%
echo 文件大小: 
dir "%output_file%" | findstr "%output_file%"
echo.
echo 统计信息:
echo - 运行进程数: %process_count%
echo - 网络连接数: %connection_count%
echo - 用户账户数: %user_count%
echo.

echo 是否要查看收集的信息？
choice /c YN /m "按Y查看，按N退出"
if %errorlevel%==1 (
    echo.
    echo 正在显示收集的信息...
    echo ========================================
    type "%output_file%"
    echo.
    echo ========================================
    echo 信息显示完毕
)

echo.
echo 感谢使用Windows系统信息收集器！
echo 收集的信息已保存到: %output_file%
echo.
pause
exit /b 0