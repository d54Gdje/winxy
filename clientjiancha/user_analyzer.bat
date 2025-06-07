@echo off
chcp 65001 >nul
setlocal enabledelayedexpansion

:: ========================================
:: Windows用户账户分析脚本
:: 版本: 1.0
:: 用途: 深度分析用户账户和权限配置
:: ========================================

title Windows用户账户分析器

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
set "output_file=user_analysis_%timestamp%.txt"

echo ========================================
echo Windows用户账户分析器
echo ========================================
echo 开始时间: %date% %time%
echo 输出文件: %output_file%
echo ========================================
echo.

echo Windows用户账户分析报告 > "%output_file%"
echo 分析时间: %date% %time% >> "%output_file%"
echo 分析工具: 用户账户分析脚本 >> "%output_file%"
echo ======================================== >> "%output_file%"
echo. >> "%output_file%"

echo [1/12] 收集所有用户账户...
echo === 所有用户账户 === >> "%output_file%"
net user >> "%output_file%"
echo. >> "%output_file%"

echo [2/12] 分析管理员组成员...
echo === 管理员组成员 === >> "%output_file%"
net localgroup Administrators >> "%output_file%"
echo. >> "%output_file%"

echo [3/12] 检查其他重要组...
echo === 其他重要用户组 === >> "%output_file%"
echo --- Power Users组 --- >> "%output_file%"
net localgroup "Power Users" 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo Power Users组不存在或无权限访问 >> "%output_file%"
echo. >> "%output_file%"

echo --- Remote Desktop Users组 --- >> "%output_file%"
net localgroup "Remote Desktop Users" 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo Remote Desktop Users组不存在或无权限访问 >> "%output_file%"
echo. >> "%output_file%"

echo --- Backup Operators组 --- >> "%output_file%"
net localgroup "Backup Operators" 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo Backup Operators组不存在或无权限访问 >> "%output_file%"
echo. >> "%output_file%"

echo [4/12] 检查隐藏用户...
echo === 隐藏用户检查 === >> "%output_file%"
echo 检查注册表隐藏用户配置... >> "%output_file%"
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo 未发现隐藏用户配置 >> "%output_file%"
echo. >> "%output_file%"

echo [5/12] 分析当前用户权限...
echo === 当前用户权限分析 === >> "%output_file%"
echo --- 当前用户基本信息 --- >> "%output_file%"
whoami >> "%output_file%"
echo. >> "%output_file%"
echo --- 当前用户权限 --- >> "%output_file%"
whoami /priv >> "%output_file%"
echo. >> "%output_file%"
echo --- 当前用户组成员身份 --- >> "%output_file%"
whoami /groups >> "%output_file%"
echo. >> "%output_file%"

echo [6/12] 检查用户详细信息...
echo === 用户详细信息 === >> "%output_file%"

:: 获取用户列表并逐个分析
for /f "skip=4 tokens=1" %%u in ('net user 2^>nul') do (
    if "%%u" neq "" if "%%u" neq "The" if "%%u" neq "command" (
        echo --- 用户 %%u 的详细信息 --- >> "%output_file%"
        net user "%%u" 2>nul >> "%output_file%"
        echo. >> "%output_file%"
    )
)

echo [7/12] 检查登录会话...
echo === 当前登录会话 === >> "%output_file%"
query user 2>nul >> "%output_file%"
if %errorlevel% neq 0 echo 无法获取登录会话信息（可能需要终端服务） >> "%output_file%"
echo. >> "%output_file%"

echo [8/12] 检查最近登录记录...
echo === 最近登录记录 === >> "%output_file%"
echo 查询最近的成功登录事件... >> "%output_file%"
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text >> "%output_file%" 2>nul
if %errorlevel% neq 0 echo 无法读取安全日志（需要管理员权限） >> "%output_file%"
echo. >> "%output_file%"

echo [9/12] 检查失败登录尝试...
echo === 失败登录尝试 === >> "%output_file%"
echo 查询最近的失败登录事件... >> "%output_file%"
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text >> "%output_file%" 2>nul
if %errorlevel% neq 0 echo 无法读取安全日志（需要管理员权限） >> "%output_file%"
echo. >> "%output_file%"

echo [10/12] 检查密码策略...
echo === 密码策略检查 === >> "%output_file%"
net accounts >> "%output_file%"
echo. >> "%output_file%"

echo [11/12] 检查用户权限分配...
echo === 用户权限分配 === >> "%output_file%"
echo 检查本地安全策略中的用户权限分配... >> "%output_file%"
secedit /export /cfg temp_security_policy.inf >nul 2>&1
if exist temp_security_policy.inf (
    echo 导出的安全策略（部分）: >> "%output_file%"
    findstr /C:"SeInteractiveLogonRight" /C:"SeRemoteInteractiveLogonRight" /C:"SeServiceLogonRight" temp_security_policy.inf >> "%output_file%"
    del temp_security_policy.inf
) else (
    echo 无法导出安全策略（需要管理员权限） >> "%output_file%"
)
echo. >> "%output_file%"

echo [12/12] 生成用户安全评估...
echo === 用户安全评估 === >> "%output_file%"

:: 统计用户信息
set total_users=0
set admin_users=0
set hidden_users=0
set failed_logins=0

:: 统计总用户数
for /f "skip=4" %%a in ('net user 2^>nul ^| find /c /v ""') do set total_users=%%a

:: 统计管理员用户数
for /f "skip=6" %%a in ('net localgroup Administrators 2^>nul ^| find /c /v ""') do set admin_users=%%a

:: 检查是否有隐藏用户
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" >nul 2>&1
if %errorlevel% equ 0 set hidden_users=1

:: 统计失败登录次数（简化版）
for /f %%a in ('wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:100 /rd:true /f:text 2^>nul ^| find /c "Event ID"') do set failed_logins=%%a

echo 用户账户统计: >> "%output_file%"
echo - 总用户数: %total_users% >> "%output_file%"
echo - 管理员用户数: %admin_users% >> "%output_file%"
echo - 隐藏用户: %hidden_users% >> "%output_file%"
echo - 最近失败登录次数: %failed_logins% >> "%output_file%"
echo. >> "%output_file%"

:: 安全风险评估
set risk_level=低
set risk_score=0

if %admin_users% gtr 5 (
    set risk_level=中
    set /a risk_score+=20
    echo [中风险] 管理员用户数量较多 ^(%admin_users%^) >> "%output_file%"
)

if %hidden_users% gtr 0 (
    set risk_level=高
    set /a risk_score+=40
    echo [高风险] 发现隐藏用户配置 >> "%output_file%"
)

if %failed_logins% gtr 20 (
    set risk_level=高
    set /a risk_score+=30
    echo [高风险] 失败登录次数异常 ^(%failed_logins%^) >> "%output_file%"
) else if %failed_logins% gtr 10 (
    set /a risk_score+=15
    echo [中风险] 失败登录次数较多 ^(%failed_logins%^) >> "%output_file%"
)

echo. >> "%output_file%"
echo 用户安全评估结果: >> "%output_file%"
echo - 风险等级: %risk_level% >> "%output_file%"
echo - 风险评分: %risk_score%/100 >> "%output_file%"
echo. >> "%output_file%"

echo 安全建议: >> "%output_file%"
if %admin_users% gtr 5 echo - 审查管理员账户的必要性，移除不需要的管理员权限 >> "%output_file%"
if %hidden_users% gtr 0 echo - 检查隐藏用户的合法性，删除恶意隐藏账户 >> "%output_file%"
if %failed_logins% gtr 10 echo - 启用账户锁定策略，防止暴力破解攻击 >> "%output_file%"
echo - 定期审查用户账户和权限 >> "%output_file%"
echo - 实施强密码策略 >> "%output_file%"
echo - 启用双因素认证 >> "%output_file%"
echo - 监控用户登录活动 >> "%output_file%"
echo. >> "%output_file%"

echo 分析完成时间: %date% %time% >> "%output_file%"

echo.
echo ========================================
echo 用户账户分析完成！
echo ========================================
echo 输出文件: %output_file%
echo.
echo 用户账户统计:
echo - 总用户数: %total_users%
echo - 管理员用户数: %admin_users%
echo - 隐藏用户: %hidden_users%
echo - 最近失败登录次数: %failed_logins%
echo - 风险等级: %risk_level%
echo - 风险评分: %risk_score%/100
echo.

if %hidden_users% gtr 0 (
    echo [警告] 检测到隐藏用户配置，建议立即检查！
    echo.
)

if %failed_logins% gtr 20 (
    echo [警告] 失败登录次数异常，可能存在暴力破解攻击！
    echo.
)

echo 是否要查看详细的用户分析结果？
choice /c YN /m "按Y查看，按N退出"
if %errorlevel%==1 (
    echo.
    echo 正在显示用户分析结果...
    echo ========================================
    type "%output_file%"
    echo.
    echo ========================================
    echo 分析结果显示完毕
)

echo.
echo 感谢使用Windows用户账户分析器！
echo 分析结果已保存到: %output_file%
echo.
pause
exit /b 0