@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ========================================
:: Windows网络连接分析脚本
:: 版本: 1.0
:: 用途: 深度分析网络连接和可疑活动
:: ========================================

title Windows网络连接分析器

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
set "output_file=network_analysis_%timestamp%.txt"

echo ========================================
echo Windows网络连接分析器
echo ========================================
echo 开始时间: %date% %time%
echo 输出文件: %output_file%
echo ========================================
echo.

echo Windows网络连接分析报告 > "%output_file%"
echo 分析时间: %date% %time% >> "%output_file%"
echo 分析工具: 网络连接分析脚本 >> "%output_file%"
echo ======================================== >> "%output_file%"
echo. >> "%output_file%"

echo [1/12] 收集所有网络连接...
echo === 所有网络连接 === >> "%output_file%"
netstat -ano >> "%output_file%"
echo. >> "%output_file%"

echo [2/12] 分析活动连接...
echo === 活动连接分析 === >> "%output_file%"
echo --- ESTABLISHED连接 --- >> "%output_file%"
netstat -ano | findstr "ESTABLISHED" >> "%output_file%"
echo. >> "%output_file%"

echo [3/12] 识别外部连接...
echo === 外部连接识别 === >> "%output_file%"
echo --- 非本地连接 --- >> "%output_file%"
netstat -ano | findstr "ESTABLISHED" | findstr /v "127.0.0.1" | findstr /v "::1" | findstr /v "0.0.0.0" >> "%output_file%"
echo. >> "%output_file%"

echo [4/12] 检查监听端口...
echo === 监听端口检查 === >> "%output_file%"
echo --- LISTENING端口 --- >> "%output_file%"
netstat -ano | findstr "LISTENING" >> "%output_file%"
echo. >> "%output_file%"

echo [5/12] 分析可疑端口...
echo === 可疑端口分析 === >> "%output_file%"
echo --- 检查常见恶意端口 --- >> "%output_file%"

:: 检查可疑端口
set suspicious_ports=4444 6666 1337 31337 8080 9999 12345 54321
for %%p in (%suspicious_ports%) do (
    echo 检查端口 %%p: >> "%output_file%"
    netstat -ano | findstr ":%%p " >> "%output_file%"
    if !errorlevel! equ 0 (
        echo [警告] 发现可疑端口 %%p 的连接！ >> "%output_file%"
    ) else (
        echo 端口 %%p 未发现连接 >> "%output_file%"
    )
    echo. >> "%output_file%"
)

echo [6/12] 匹配进程信息...
echo === 连接进程匹配 === >> "%output_file%"
echo --- 外部连接对应的进程 --- >> "%output_file%"

:: 创建临时文件存储外部连接
netstat -ano | findstr "ESTABLISHED" | findstr /v "127.0.0.1" | findstr /v "::1" | findstr /v "0.0.0.0" > temp_connections.txt

for /f "tokens=5" %%p in (temp_connections.txt) do (
    echo 进程ID %%p 的详细信息: >> "%output_file%"
    tasklist /fi "PID eq %%p" /v >> "%output_file%"
    echo. >> "%output_file%"
)

if exist temp_connections.txt del temp_connections.txt

echo [7/12] 收集路由表...
echo === 路由表信息 === >> "%output_file%"
route print >> "%output_file%"
echo. >> "%output_file%"

echo [8/12] 收集ARP表...
echo === ARP表信息 === >> "%output_file%"
arp -a >> "%output_file%"
echo. >> "%output_file%"

echo [9/12] 检查DNS配置...
echo === DNS配置检查 === >> "%output_file%"
nslookup >> "%output_file%" 2>&1
echo. >> "%output_file%"

echo [10/12] 收集网络接口信息...
echo === 网络接口信息 === >> "%output_file%"
ipconfig /all >> "%output_file%"
echo. >> "%output_file%"

echo [11/12] 检查网络共享...
echo === 网络共享检查 === >> "%output_file%"
net share >> "%output_file%"
echo. >> "%output_file%"

echo [12/12] 生成网络安全评估...
echo === 网络安全评估 === >> "%output_file%"

:: 统计各种连接数量
for /f %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| find /c /v ""') do set total_established=%%a
for /f %%a in ('netstat -ano ^| findstr "ESTABLISHED" ^| findstr /v "127.0.0.1" ^| findstr /v "::1" ^| findstr /v "0.0.0.0" ^| find /c /v ""') do set external_connections=%%a
for /f %%a in ('netstat -ano ^| findstr "LISTENING" ^| find /c /v ""') do set listening_ports=%%a

echo 网络连接统计: >> "%output_file%"
echo - 总活动连接数: %total_established% >> "%output_file%"
echo - 外部连接数: %external_connections% >> "%output_file%"
echo - 监听端口数: %listening_ports% >> "%output_file%"
echo. >> "%output_file%"

:: 风险评估
set risk_level=低
set risk_score=0

if %external_connections% gtr 20 (
    set risk_level=高
    set /a risk_score+=30
    echo [高风险] 外部连接数量异常 ^(%external_connections%^) >> "%output_file%"
) else if %external_connections% gtr 10 (
    set risk_level=中
    set /a risk_score+=15
    echo [中风险] 外部连接数量较多 ^(%external_connections%^) >> "%output_file%"
)

if %listening_ports% gtr 50 (
    set /a risk_score+=20
    echo [风险] 监听端口数量较多 ^(%listening_ports%^) >> "%output_file%"
)

echo. >> "%output_file%"
echo 网络安全评估结果: >> "%output_file%"
echo - 风险等级: %risk_level% >> "%output_file%"
echo - 风险评分: %risk_score%/100 >> "%output_file%"
echo. >> "%output_file%"

echo 安全建议: >> "%output_file%"
if %external_connections% gtr 10 echo - 检查外部连接的合法性 >> "%output_file%"
if %listening_ports% gtr 50 echo - 关闭不必要的监听端口 >> "%output_file%"
echo - 定期监控网络连接 >> "%output_file%"
echo - 启用防火墙保护 >> "%output_file%"
echo - 使用网络监控工具 >> "%output_file%"
echo. >> "%output_file%"

echo 分析完成时间: %date% %time% >> "%output_file%"

echo.
echo ========================================
echo 网络连接分析完成！
echo ========================================
echo 输出文件: %output_file%
echo.
echo 网络连接统计:
echo - 总活动连接数: %total_established%
echo - 外部连接数: %external_connections%
echo - 监听端口数: %listening_ports%
echo - 风险等级: %risk_level%
echo - 风险评分: %risk_score%/100
echo.

if %external_connections% gtr 10 (
    echo [警告] 检测到较多外部连接，建议进一步检查！
    echo.
)

echo 是否要查看详细的网络分析结果？
choice /c YN /m "按Y查看，按N退出"
if %errorlevel%==1 (
    echo.
    echo 正在显示网络分析结果...
    echo ========================================
    type "%output_file%"
    echo.
    echo ========================================
    echo 分析结果显示完毕
)

echo.
echo 感谢使用Windows网络连接分析器！
echo 分析结果已保存到: %output_file%
echo.
pause
exit /b 0