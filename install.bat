@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ========================================
:: WinXY Windows紧急响应系统 - 安装脚本
:: 版本: 1.0
:: 用途: 自动安装和配置WinXY系统
:: ========================================

title WinXY Windows紧急响应系统 - 安装程序

:: 检查管理员权限
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo.
    echo [错误] 需要管理员权限运行安装程序
    echo 请右键点击install.bat，选择"以管理员身份运行"
    echo.
    pause
    exit /b 1
)

:: 设置颜色
color 0B

echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                    WinXY Windows紧急响应系统 - 安装程序                     ║
echo ║                           版本: 1.0                                         ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.
echo 欢迎使用WinXY Windows紧急响应系统安装程序！
echo.
echo 此安装程序将：
echo [1] 检查系统环境
echo [2] 创建必要的目录结构
echo [3] 检查和安装Python依赖
echo [4] 配置系统设置
echo [5] 验证安装结果
echo.

echo 是否继续安装？
choice /c YN /m "按Y继续，按N取消"
if %errorlevel%==2 (
    echo 安装已取消。
    pause
    exit /b 0
)

echo.
echo ========================================
echo 开始安装 WinXY 系统...
echo ========================================
echo.

:: 步骤1：检查系统环境
echo [1/5] 检查系统环境...
echo.

echo 检查Windows版本...
for /f "tokens=4-5 delims=. " %%i in ('ver') do set VERSION=%%i.%%j
echo Windows版本: %VERSION%

:: 检查是否为Windows 10或更高版本
for /f "tokens=1 delims=." %%a in ("%VERSION%") do set MAJOR_VERSION=%%a
if %MAJOR_VERSION% LSS 10 (
    echo [警告] 建议使用Windows 10或更高版本以获得最佳体验
    timeout /t 3 >nul
)

echo 检查系统架构...
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    echo 系统架构: 64位
) else (
    echo 系统架构: 32位
)

echo 检查可用磁盘空间...
for /f "tokens=3" %%a in ('dir /-c ^| findstr "bytes free"') do set FREE_SPACE=%%a
echo 可用磁盘空间: %FREE_SPACE% 字节

echo.
echo [✓] 系统环境检查完成
echo.

:: 步骤2：创建目录结构
echo [2/5] 创建目录结构...
echo.

set DIRECTORIES=reports logs uploads temp clientjiancha

for %%d in (%DIRECTORIES%) do (
    if not exist "%%d" (
        mkdir "%%d"
        echo 创建目录: %%d
    ) else (
        echo 目录已存在: %%d
    )
)

echo.
echo [✓] 目录结构创建完成
echo.

:: 步骤3：检查Python环境
echo [3/5] 检查Python环境...
echo.

python --version >nul 2>&1
if %errorlevel% neq 0 (
    echo [警告] 未检测到Python
    echo.
    echo Python是可选组件，用于以下功能：
    echo - Web界面 (winxy_web_server.py)
    echo - Python版信息收集脚本
    echo.
    echo 您可以：
    echo 1. 继续安装（仅使用批处理功能）
    echo 2. 手动安装Python后重新运行安装程序
    echo.
    echo 下载Python: https://www.python.org/downloads/
    echo.
    choice /c 12 /m "选择操作 (1=继续, 2=退出安装Python)"
    if !errorlevel!==2 (
        echo.
        echo 请安装Python后重新运行安装程序。
        pause
        exit /b 0
    )
    set PYTHON_AVAILABLE=false
) else (
    python --version
    set PYTHON_AVAILABLE=true
    
    echo.
    echo 检查Python依赖包...
    
    :: 检查Flask
    python -c "import flask" >nul 2>&1
    if !errorlevel! neq 0 (
        echo 安装Flask...
        pip install flask
    ) else (
        echo Flask已安装
    )
    
    :: 检查Flask-CORS
    python -c "import flask_cors" >nul 2>&1
    if !errorlevel! neq 0 (
        echo 安装Flask-CORS...
        pip install flask-cors
    ) else (
        echo Flask-CORS已安装
    )
    
    :: 检查psutil
    python -c "import psutil" >nul 2>&1
    if !errorlevel! neq 0 (
        echo 安装psutil...
        pip install psutil
    ) else (
        echo psutil已安装
    )
)

echo.
echo [✓] Python环境检查完成
echo.

:: 步骤4：配置系统设置
echo [4/5] 配置系统设置...
echo.

:: 检查PowerShell执行策略
echo 检查PowerShell执行策略...
powershell -Command "Get-ExecutionPolicy" >temp_policy.txt 2>nul
if exist temp_policy.txt (
    set /p CURRENT_POLICY=<temp_policy.txt
    del temp_policy.txt
    echo 当前PowerShell执行策略: !CURRENT_POLICY!
    
    if "!CURRENT_POLICY!"=="Restricted" (
        echo [警告] PowerShell执行策略为Restricted
        echo 这可能影响security_checker.ps1脚本的运行
        echo.
        choice /c YN /m "是否设置为RemoteSigned策略？(推荐)"
        if !errorlevel!==1 (
            powershell -Command "Set-ExecutionPolicy RemoteSigned -Force" >nul 2>&1
            echo PowerShell执行策略已设置为RemoteSigned
        )
    )
) else (
    echo 无法检查PowerShell执行策略
)

:: 创建快捷方式（可选）
echo.
choice /c YN /m "是否在桌面创建快捷方式？"
if !errorlevel!==1 (
    set DESKTOP=%USERPROFILE%\Desktop
    set SHORTCUT_PATH=!DESKTOP!\WinXY紧急响应系统.lnk
    
    :: 使用PowerShell创建快捷方式
    powershell -Command "$WshShell = New-Object -comObject WScript.Shell; $Shortcut = $WshShell.CreateShortcut('%SHORTCUT_PATH%'); $Shortcut.TargetPath = '%CD%\winxy_emergency_response.bat'; $Shortcut.WorkingDirectory = '%CD%'; $Shortcut.Description = 'WinXY Windows紧急响应系统'; $Shortcut.Save()" >nul 2>&1
    
    if exist "!SHORTCUT_PATH!" (
        echo 桌面快捷方式创建成功
    ) else (
        echo 快捷方式创建失败
    )
)

echo.
echo [✓] 系统设置配置完成
echo.

:: 步骤5：验证安装
echo [5/5] 验证安装结果...
echo.

echo 检查主要文件...
set MAIN_FILES=winxy_emergency_response.bat winxy_web_server.py config.json emergency_commands.json

for %%f in (%MAIN_FILES%) do (
    if exist "%%f" (
        echo [✓] %%f
    ) else (
        echo [✗] %%f - 文件缺失！
    )
)

echo.
echo 检查目录结构...
for %%d in (%DIRECTORIES%) do (
    if exist "%%d" (
        echo [✓] %%d\
    ) else (
        echo [✗] %%d\ - 目录缺失！
    )
)

echo.
echo 检查clientjiancha脚本...
set CLIENT_SCRIPTS=system_info_collector.bat network_analyzer.bat user_analyzer.bat system_info_collector.py process_analyzer.py security_checker.ps1

for %%s in (%CLIENT_SCRIPTS%) do (
    if exist "clientjiancha\%%s" (
        echo [✓] clientjiancha\%%s
    ) else (
        echo [✗] clientjiancha\%%s - 文件缺失！
    )
)

echo.
echo ========================================
echo 安装完成！
echo ========================================
echo.

echo 安装摘要:
echo - 系统版本: Windows %VERSION%
echo - Python可用: %PYTHON_AVAILABLE%
echo - 安装目录: %CD%
echo - 配置文件: config.json
echo.

echo 使用方法:
echo.
echo 方法1 - 批处理界面（推荐）:
echo   右键点击 winxy_emergency_response.bat
echo   选择"以管理员身份运行"
echo.

if "%PYTHON_AVAILABLE%"=="true" (
    echo 方法2 - Web界面:
    echo   运行: python winxy_web_server.py
    echo   浏览器访问: http://localhost:12000
    echo.
)

echo 方法3 - 直接运行信息收集脚本:
echo   进入 clientjiancha 目录
echo   运行相应的 .bat 或 .py 脚本
echo.

echo 重要提示:
echo - 建议以管理员权限运行以获取完整信息
echo - 所有批处理脚本都有防闪退设计
echo - 分析结果保存在 reports 目录
echo - 详细使用说明请查看 README.md
echo.

echo 感谢使用 WinXY Windows紧急响应系统！
echo.

choice /c YN /m "是否现在启动主程序？"
if %errorlevel%==1 (
    echo.
    echo 正在启动主程序...
    start "" "%CD%\winxy_emergency_response.bat"
)

echo.
echo 安装程序结束。
pause
exit /b 0