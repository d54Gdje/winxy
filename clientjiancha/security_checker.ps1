# ========================================
# Windows安全检查脚本 (PowerShell版本)
# 版本: 1.0
# 用途: 深度安全检查和威胁检测
# 注意: 此脚本使用PowerShell，需要明确标注
# ========================================

param(
    [switch]$Detailed,
    [string]$OutputPath = "."
)

# 设置执行策略（如果需要）
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force

# 输出文件设置
$timestamp = Get-Date -Format "yyyy-MM-dd_HH-mm-ss"
$outputFile = Join-Path $OutputPath "security_check_$timestamp.txt"

Write-Host "========================================" -ForegroundColor Green
Write-Host "Windows安全检查器 - PowerShell版本" -ForegroundColor Green
Write-Host "========================================" -ForegroundColor Green
Write-Host "开始时间: $(Get-Date)" -ForegroundColor Yellow
Write-Host "输出文件: $outputFile" -ForegroundColor Yellow
Write-Host "========================================" -ForegroundColor Green
Write-Host ""

# 初始化输出文件
@"
Windows安全检查报告 - PowerShell版本
检查时间: $(Get-Date)
检查工具: PowerShell安全检查脚本
========================================

"@ | Out-File -FilePath $outputFile -Encoding UTF8

function Write-Section {
    param($Title, $Content)
    
    $section = @"

=== $Title ===
$Content

"@
    Add-Content -Path $outputFile -Value $section -Encoding UTF8
    Write-Host "[完成] $Title" -ForegroundColor Green
}

function Get-SuspiciousProcesses {
    Write-Host "[1/15] 检查可疑进程..." -ForegroundColor Cyan
    
    $suspiciousNames = @(
        'cmd.exe', 'powershell.exe', 'nc.exe', 'netcat.exe',
        'psexec.exe', 'mimikatz.exe', 'procdump.exe', 'wce.exe',
        'fgdump.exe', 'pwdump.exe', 'gsecdump.exe'
    )
    
    $processes = Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, StartTime
    $suspicious = @()
    
    foreach ($proc in $processes) {
        if ($proc.Name -in $suspiciousNames) {
            $suspicious += $proc
        }
    }
    
    $content = "总进程数: $($processes.Count)`n"
    $content += "可疑进程数: $($suspicious.Count)`n`n"
    
    if ($suspicious.Count -gt 0) {
        $content += "发现的可疑进程:`n"
        foreach ($proc in $suspicious) {
            $content += "- $($proc.Name) (PID: $($proc.Id), 路径: $($proc.Path))`n"
        }
    } else {
        $content += "未发现明显可疑进程"
    }
    
    Write-Section "可疑进程检查" $content
    return $suspicious.Count
}

function Get-NetworkConnections {
    Write-Host "[2/15] 分析网络连接..." -ForegroundColor Cyan
    
    $connections = Get-NetTCPConnection | Where-Object { $_.State -eq 'Established' }
    $external = $connections | Where-Object { 
        $_.RemoteAddress -notmatch '^127\.' -and 
        $_.RemoteAddress -ne '::1' -and 
        $_.RemoteAddress -ne '0.0.0.0' 
    }
    
    $suspicious = $external | Where-Object {
        $_.RemotePort -in @(4444, 6666, 1337, 31337, 8080, 9999, 12345, 54321)
    }
    
    $content = "总连接数: $($connections.Count)`n"
    $content += "外部连接数: $($external.Count)`n"
    $content += "可疑连接数: $($suspicious.Count)`n`n"
    
    if ($external.Count -gt 0) {
        $content += "外部连接详情:`n"
        foreach ($conn in $external | Select-Object -First 20) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.Name } else { "Unknown" }
            $content += "- $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$processName]`n"
        }
    }
    
    if ($suspicious.Count -gt 0) {
        $content += "`n可疑连接详情:`n"
        foreach ($conn in $suspicious) {
            $process = Get-Process -Id $conn.OwningProcess -ErrorAction SilentlyContinue
            $processName = if ($process) { $process.Name } else { "Unknown" }
            $content += "- [警告] $($conn.LocalAddress):$($conn.LocalPort) -> $($conn.RemoteAddress):$($conn.RemotePort) [$processName]`n"
        }
    }
    
    Write-Section "网络连接分析" $content
    return @($external.Count, $suspicious.Count)
}

function Get-UserAccounts {
    Write-Host "[3/15] 检查用户账户..." -ForegroundColor Cyan
    
    $users = Get-LocalUser
    $admins = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
    $hiddenUsers = @()
    
    # 检查隐藏用户
    try {
        $hiddenUsersReg = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" -ErrorAction SilentlyContinue
        if ($hiddenUsersReg) {
            $hiddenUsers = $hiddenUsersReg.PSObject.Properties | Where-Object { $_.Value -eq 0 } | Select-Object -ExpandProperty Name
        }
    } catch {
        # 忽略错误
    }
    
    $content = "总用户数: $($users.Count)`n"
    $content += "管理员数: $($admins.Count)`n"
    $content += "隐藏用户数: $($hiddenUsers.Count)`n`n"
    
    $content += "用户账户详情:`n"
    foreach ($user in $users) {
        $isAdmin = $user.Name -in $admins.Name
        $isHidden = $user.Name -in $hiddenUsers
        $status = @()
        if ($isAdmin) { $status += "管理员" }
        if ($isHidden) { $status += "隐藏" }
        if (-not $user.Enabled) { $status += "禁用" }
        
        $statusText = if ($status.Count -gt 0) { " [$($status -join ', ')]" } else { "" }
        $content += "- $($user.Name)$statusText`n"
    }
    
    if ($hiddenUsers.Count -gt 0) {
        $content += "`n发现隐藏用户:`n"
        foreach ($hidden in $hiddenUsers) {
            $content += "- [警告] $hidden`n"
        }
    }
    
    Write-Section "用户账户检查" $content
    return @($users.Count, $admins.Count, $hiddenUsers.Count)
}

function Get-StartupPrograms {
    Write-Host "[4/15] 检查启动项..." -ForegroundColor Cyan
    
    $startupLocations = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    $content = "启动项检查:`n`n"
    $totalStartup = 0
    
    foreach ($location in $startupLocations) {
        try {
            $items = Get-ItemProperty -Path $location -ErrorAction SilentlyContinue
            if ($items) {
                $content += "位置: $location`n"
                $properties = $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                $totalStartup += $properties.Count
                
                foreach ($prop in $properties) {
                    $content += "- $($prop.Name): $($prop.Value)`n"
                }
                $content += "`n"
            }
        } catch {
            $content += "无法访问: $location`n`n"
        }
    }
    
    # 检查启动文件夹
    $startupFolder = "$env:APPDATA\Microsoft\Windows\Start Menu\Programs\Startup"
    if (Test-Path $startupFolder) {
        $startupFiles = Get-ChildItem -Path $startupFolder
        if ($startupFiles.Count -gt 0) {
            $content += "启动文件夹 ($startupFolder):`n"
            foreach ($file in $startupFiles) {
                $content += "- $($file.Name)`n"
                $totalStartup++
            }
        }
    }
    
    $content = "总启动项数: $totalStartup`n`n" + $content
    
    Write-Section "启动项检查" $content
    return $totalStartup
}

function Get-Services {
    Write-Host "[5/15] 检查系统服务..." -ForegroundColor Cyan
    
    $services = Get-Service
    $running = $services | Where-Object { $_.Status -eq 'Running' }
    $stopped = $services | Where-Object { $_.Status -eq 'Stopped' }
    
    # 检查可疑服务
    $suspiciousServices = $running | Where-Object {
        $_.Name -match 'remote|telnet|ssh|vnc|rdp' -and
        $_.Name -notmatch 'RemoteRegistry|TermService|WinRM'
    }
    
    $content = "总服务数: $($services.Count)`n"
    $content += "运行中服务: $($running.Count)`n"
    $content += "已停止服务: $($stopped.Count)`n"
    $content += "可疑服务: $($suspiciousServices.Count)`n`n"
    
    if ($suspiciousServices.Count -gt 0) {
        $content += "可疑服务详情:`n"
        foreach ($service in $suspiciousServices) {
            $content += "- [警告] $($service.Name) ($($service.DisplayName))`n"
        }
    }
    
    Write-Section "系统服务检查" $content
    return $suspiciousServices.Count
}

function Get-FirewallStatus {
    Write-Host "[6/15] 检查防火墙状态..." -ForegroundColor Cyan
    
    try {
        $profiles = Get-NetFirewallProfile
        $content = "防火墙配置文件状态:`n"
        
        foreach ($profile in $profiles) {
            $content += "- $($profile.Name): $($profile.Enabled)`n"
        }
        
        $rules = Get-NetFirewallRule | Where-Object { $_.Enabled -eq $true }
        $content += "`n活动防火墙规则数: $($rules.Count)`n"
        
        # 检查入站规则
        $inboundRules = $rules | Where-Object { $_.Direction -eq 'Inbound' -and $_.Action -eq 'Allow' }
        $content += "入站允许规则: $($inboundRules.Count)`n"
        
        if ($inboundRules.Count -gt 50) {
            $content += "[警告] 入站允许规则数量较多，可能存在安全风险`n"
        }
        
    } catch {
        $content = "无法获取防火墙状态: $($_.Exception.Message)"
    }
    
    Write-Section "防火墙状态检查" $content
}

function Get-EventLogs {
    Write-Host "[7/15] 分析安全事件日志..." -ForegroundColor Cyan
    
    $content = "安全事件日志分析:`n`n"
    
    # 检查失败登录
    try {
        $failedLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4625} -MaxEvents 100 -ErrorAction SilentlyContinue
        $content += "最近失败登录次数: $($failedLogins.Count)`n"
        
        if ($failedLogins.Count -gt 10) {
            $content += "[警告] 失败登录次数较多，可能存在暴力破解攻击`n"
            
            # 分析失败登录的IP地址
            $ipPattern = '\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
            $ips = @{}
            foreach ($event in $failedLogins | Select-Object -First 50) {
                $matches = [regex]::Matches($event.Message, $ipPattern)
                foreach ($match in $matches) {
                    $ip = $match.Value
                    if ($ip -ne '127.0.0.1' -and $ip -ne '0.0.0.0') {
                        $ips[$ip] = ($ips[$ip] ?? 0) + 1
                    }
                }
            }
            
            if ($ips.Count -gt 0) {
                $content += "失败登录来源IP统计:`n"
                $sortedIps = $ips.GetEnumerator() | Sort-Object Value -Descending | Select-Object -First 10
                foreach ($ip in $sortedIps) {
                    $content += "- $($ip.Key): $($ip.Value) 次`n"
                }
            }
        }
    } catch {
        $content += "无法读取失败登录事件`n"
    }
    
    # 检查成功登录
    try {
        $successLogins = Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 -ErrorAction SilentlyContinue
        $content += "`n最近成功登录次数: $($successLogins.Count)`n"
    } catch {
        $content += "`n无法读取成功登录事件`n"
    }
    
    # 检查系统启动事件
    try {
        $systemStarts = Get-WinEvent -FilterHashtable @{LogName='System'; ID=6005} -MaxEvents 10 -ErrorAction SilentlyContinue
        $content += "最近系统启动次数: $($systemStarts.Count)`n"
    } catch {
        $content += "无法读取系统启动事件`n"
    }
    
    Write-Section "安全事件日志分析" $content
    return $failedLogins.Count
}

function Get-InstalledSoftware {
    Write-Host "[8/15] 检查安装的软件..." -ForegroundColor Cyan
    
    $software = Get-WmiObject -Class Win32_Product | Select-Object Name, Version, Vendor | Sort-Object Name
    
    # 检查可疑软件
    $suspiciousKeywords = @('remote', 'vnc', 'teamviewer', 'anydesk', 'hack', 'crack', 'keygen')
    $suspicious = $software | Where-Object {
        $name = $_.Name.ToLower()
        $suspiciousKeywords | Where-Object { $name -match $_ }
    }
    
    $content = "已安装软件数量: $($software.Count)`n"
    $content += "可疑软件数量: $($suspicious.Count)`n`n"
    
    if ($suspicious.Count -gt 0) {
        $content += "可疑软件列表:`n"
        foreach ($app in $suspicious) {
            $content += "- [警告] $($app.Name) (版本: $($app.Version), 厂商: $($app.Vendor))`n"
        }
    }
    
    if ($Detailed) {
        $content += "`n所有已安装软件:`n"
        foreach ($app in $software | Select-Object -First 50) {
            $content += "- $($app.Name) (版本: $($app.Version))`n"
        }
    }
    
    Write-Section "安装软件检查" $content
    return $suspicious.Count
}

function Get-ScheduledTasks {
    Write-Host "[9/15] 检查计划任务..." -ForegroundColor Cyan
    
    $tasks = Get-ScheduledTask | Where-Object { $_.State -eq 'Ready' }
    $userTasks = $tasks | Where-Object { $_.Principal.UserId -notmatch 'SYSTEM|LOCAL SERVICE|NETWORK SERVICE' }
    
    $content = "总计划任务数: $($tasks.Count)`n"
    $content += "用户创建任务数: $($userTasks.Count)`n`n"
    
    if ($userTasks.Count -gt 0) {
        $content += "用户创建的计划任务:`n"
        foreach ($task in $userTasks | Select-Object -First 20) {
            $content += "- $($task.TaskName) (用户: $($task.Principal.UserId))`n"
        }
    }
    
    Write-Section "计划任务检查" $content
    return $userTasks.Count
}

function Get-SystemIntegrity {
    Write-Host "[10/15] 检查系统完整性..." -ForegroundColor Cyan
    
    $content = "系统完整性检查:`n`n"
    
    # 检查系统文件
    try {
        $sfcResult = & sfc /verifyonly 2>&1
        $content += "系统文件检查结果:`n$sfcResult`n`n"
    } catch {
        $content += "无法执行系统文件检查`n`n"
    }
    
    # 检查Windows Defender状态
    try {
        $defender = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defender) {
            $content += "Windows Defender状态:`n"
            $content += "- 实时保护: $($defender.RealTimeProtectionEnabled)`n"
            $content += "- 反恶意软件: $($defender.AntivirusEnabled)`n"
            $content += "- 防火墙: $($defender.FirewallEnabled)`n"
            $content += "- 最后扫描: $($defender.LastFullScanDateTime)`n"
        }
    } catch {
        $content += "无法获取Windows Defender状态`n"
    }
    
    Write-Section "系统完整性检查" $content
}

function Get-RegistryAnalysis {
    Write-Host "[11/15] 分析注册表关键项..." -ForegroundColor Cyan
    
    $content = "注册表关键项分析:`n`n"
    
    # 检查自动运行项
    $autorunKeys = @(
        "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run"
    )
    
    foreach ($key in $autorunKeys) {
        try {
            $items = Get-ItemProperty -Path $key -ErrorAction SilentlyContinue
            if ($items) {
                $content += "自动运行项 ($key):`n"
                $properties = $items.PSObject.Properties | Where-Object { $_.Name -notmatch '^PS' }
                foreach ($prop in $properties) {
                    $content += "- $($prop.Name): $($prop.Value)`n"
                }
                $content += "`n"
            }
        } catch {
            $content += "无法访问: $key`n"
        }
    }
    
    Write-Section "注册表分析" $content
}

function Get-FileSystemAnalysis {
    Write-Host "[12/15] 分析文件系统..." -ForegroundColor Cyan
    
    $content = "文件系统分析:`n`n"
    
    # 检查临时目录
    $tempDirs = @($env:TEMP, $env:TMP, "C:\Windows\Temp")
    foreach ($dir in $tempDirs) {
        if (Test-Path $dir) {
            $files = Get-ChildItem -Path $dir -File -ErrorAction SilentlyContinue
            $content += "临时目录 $dir 文件数: $($files.Count)`n"
            
            # 检查可疑文件
            $suspicious = $files | Where-Object { 
                $_.Extension -in @('.exe', '.bat', '.cmd', '.ps1', '.vbs') -and
                $_.CreationTime -gt (Get-Date).AddDays(-7)
            }
            
            if ($suspicious.Count -gt 0) {
                $content += "- [警告] 发现 $($suspicious.Count) 个最近创建的可执行文件`n"
            }
        }
    }
    
    Write-Section "文件系统分析" $content
}

function Get-NetworkShares {
    Write-Host "[13/15] 检查网络共享..." -ForegroundColor Cyan
    
    $shares = Get-SmbShare -ErrorAction SilentlyContinue
    
    $content = "网络共享检查:`n`n"
    $content += "共享数量: $($shares.Count)`n`n"
    
    if ($shares.Count -gt 0) {
        $content += "共享详情:`n"
        foreach ($share in $shares) {
            $content += "- $($share.Name): $($share.Path) (类型: $($share.ShareType))`n"
        }
    }
    
    Write-Section "网络共享检查" $content
}

function Get-USBDevices {
    Write-Host "[14/15] 检查USB设备历史..." -ForegroundColor Cyan
    
    $content = "USB设备历史检查:`n`n"
    
    try {
        $usbDevices = Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Enum\USBSTOR\*\*" -ErrorAction SilentlyContinue
        $content += "检测到的USB存储设备数量: $($usbDevices.Count)`n`n"
        
        if ($usbDevices.Count -gt 0) {
            $content += "USB设备详情:`n"
            foreach ($device in $usbDevices | Select-Object -First 10) {
                $friendlyName = $device.FriendlyName ?? "未知设备"
                $content += "- $friendlyName`n"
            }
        }
    } catch {
        $content += "无法读取USB设备历史`n"
    }
    
    Write-Section "USB设备历史检查" $content
}

function Get-ThreatAssessment {
    param(
        $SuspiciousProcesses,
        $ExternalConnections,
        $SuspiciousConnections,
        $AdminUsers,
        $HiddenUsers,
        $SuspiciousServices,
        $FailedLogins,
        $SuspiciousSoftware,
        $UserTasks
    )
    
    Write-Host "[15/15] 生成威胁评估..." -ForegroundColor Cyan
    
    $threatScore = 0
    $threats = @()
    
    # 评分规则
    if ($SuspiciousProcesses -gt 0) {
        $threatScore += $SuspiciousProcesses * 20
        $threats += "发现 $SuspiciousProcesses 个可疑进程"
    }
    
    if ($SuspiciousConnections -gt 0) {
        $threatScore += $SuspiciousConnections * 25
        $threats += "发现 $SuspiciousConnections 个可疑网络连接"
    }
    
    if ($ExternalConnections -gt 20) {
        $threatScore += 15
        $threats += "外部网络连接数量异常 ($ExternalConnections)"
    }
    
    if ($HiddenUsers -gt 0) {
        $threatScore += $HiddenUsers * 30
        $threats += "发现 $HiddenUsers 个隐藏用户账户"
    }
    
    if ($AdminUsers -gt 5) {
        $threatScore += 10
        $threats += "管理员账户数量较多 ($AdminUsers)"
    }
    
    if ($FailedLogins -gt 20) {
        $threatScore += 20
        $threats += "失败登录次数异常 ($FailedLogins)"
    }
    
    if ($SuspiciousSoftware -gt 0) {
        $threatScore += $SuspiciousSoftware * 15
        $threats += "发现 $SuspiciousSoftware 个可疑软件"
    }
    
    # 确定威胁等级
    $threatLevel = switch ($threatScore) {
        { $_ -ge 80 } { "严重"; break }
        { $_ -ge 50 } { "高"; break }
        { $_ -ge 20 } { "中"; break }
        default { "低" }
    }
    
    $content = "威胁评估结果:`n"
    $content += "威胁等级: $threatLevel`n"
    $content += "威胁评分: $threatScore/100`n"
    $content += "发现问题数: $($threats.Count)`n`n"
    
    if ($threats.Count -gt 0) {
        $content += "发现的威胁:`n"
        foreach ($threat in $threats) {
            $content += "- $threat`n"
        }
        $content += "`n"
    }
    
    $content += "安全建议:`n"
    if ($SuspiciousProcesses -gt 0) { $content += "- 立即检查可疑进程的合法性`n" }
    if ($SuspiciousConnections -gt 0) { $content += "- 断开可疑网络连接`n" }
    if ($HiddenUsers -gt 0) { $content += "- 检查隐藏用户账户的合法性`n" }
    if ($FailedLogins -gt 20) { $content += "- 启用账户锁定策略`n" }
    $content += "- 定期更新系统和软件`n"
    $content += "- 启用实时防护`n"
    $content += "- 定期备份重要数据`n"
    
    Write-Section "威胁评估" $content
    
    return @{
        Level = $threatLevel
        Score = $threatScore
        Threats = $threats
    }
}

# 主执行流程
try {
    $suspiciousProcesses = Get-SuspiciousProcesses
    $networkStats = Get-NetworkConnections
    $userStats = Get-UserAccounts
    $startupCount = Get-StartupPrograms
    $suspiciousServices = Get-Services
    Get-FirewallStatus
    $failedLogins = Get-EventLogs
    $suspiciousSoftware = Get-InstalledSoftware
    $userTasks = Get-ScheduledTasks
    Get-SystemIntegrity
    Get-RegistryAnalysis
    Get-FileSystemAnalysis
    Get-NetworkShares
    Get-USBDevices
    
    $assessment = Get-ThreatAssessment -SuspiciousProcesses $suspiciousProcesses -ExternalConnections $networkStats[0] -SuspiciousConnections $networkStats[1] -AdminUsers $userStats[1] -HiddenUsers $userStats[2] -SuspiciousServices $suspiciousServices -FailedLogins $failedLogins -SuspiciousSoftware $suspiciousSoftware -UserTasks $userTasks
    
    # 添加检查完成信息
    $summary = @"

========================================
安全检查完成
========================================
检查完成时间: $(Get-Date)
威胁等级: $($assessment.Level)
威胁评分: $($assessment.Score)/100
发现问题: $($assessment.Threats.Count) 个

报告文件: $outputFile
========================================
"@
    
    Add-Content -Path $outputFile -Value $summary -Encoding UTF8
    
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "安全检查完成！" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "报告文件: $outputFile" -ForegroundColor Yellow
    Write-Host "威胁等级: $($assessment.Level)" -ForegroundColor $(if ($assessment.Level -eq "严重" -or $assessment.Level -eq "高") { "Red" } elseif ($assessment.Level -eq "中") { "Yellow" } else { "Green" })
    Write-Host "威胁评分: $($assessment.Score)/100" -ForegroundColor Yellow
    Write-Host "发现问题: $($assessment.Threats.Count) 个" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Green
    
    if ($assessment.Threats.Count -gt 0) {
        Write-Host ""
        Write-Host "发现的主要威胁:" -ForegroundColor Red
        foreach ($threat in $assessment.Threats) {
            Write-Host "- $threat" -ForegroundColor Red
        }
    }
    
    Write-Host ""
    $viewReport = Read-Host "是否要查看详细报告？(Y/N)"
    if ($viewReport -eq 'Y' -or $viewReport -eq 'y') {
        Get-Content -Path $outputFile -Encoding UTF8 | Out-Host
    }
    
} catch {
    Write-Host "检查过程中发生错误: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "错误详情: $($_.Exception.StackTrace)" -ForegroundColor Red
}

Write-Host ""
Write-Host "感谢使用Windows安全检查器！" -ForegroundColor Green
Read-Host "按回车键退出"