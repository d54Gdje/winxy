#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows系统信息收集脚本 (Python版本)
版本: 1.0
用途: 使用Python收集详细的Windows系统信息
"""

import os
import sys
import json
import subprocess
import datetime
import platform
import psutil
import socket
import winreg
from pathlib import Path

class WindowsSystemCollector:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.output_file = f"system_info_python_{self.timestamp}.json"
        self.data = {
            'collection_info': {
                'timestamp': self.timestamp,
                'tool': 'Python脚本',
                'version': '1.0'
            }
        }
    
    def run_command(self, command, shell=True):
        """执行系统命令并返回结果"""
        try:
            result = subprocess.run(command, shell=shell, capture_output=True, 
                                  text=True, encoding='utf-8', errors='ignore')
            return result.stdout
        except Exception as e:
            return f"命令执行失败: {str(e)}"
    
    def collect_system_info(self):
        """收集系统基本信息"""
        print("[1/15] 收集系统基本信息...")
        
        self.data['system_info'] = {
            'hostname': socket.gethostname(),
            'platform': platform.platform(),
            'system': platform.system(),
            'release': platform.release(),
            'version': platform.version(),
            'machine': platform.machine(),
            'processor': platform.processor(),
            'architecture': platform.architecture(),
            'boot_time': datetime.datetime.fromtimestamp(psutil.boot_time()).isoformat()
        }
    
    def collect_hardware_info(self):
        """收集硬件信息"""
        print("[2/15] 收集硬件信息...")
        
        # CPU信息
        cpu_info = {
            'physical_cores': psutil.cpu_count(logical=False),
            'logical_cores': psutil.cpu_count(logical=True),
            'cpu_freq': psutil.cpu_freq()._asdict() if psutil.cpu_freq() else None,
            'cpu_percent': psutil.cpu_percent(interval=1)
        }
        
        # 内存信息
        memory = psutil.virtual_memory()
        memory_info = {
            'total': memory.total,
            'available': memory.available,
            'percent': memory.percent,
            'used': memory.used,
            'free': memory.free
        }
        
        # 磁盘信息
        disk_info = []
        for partition in psutil.disk_partitions():
            try:
                usage = psutil.disk_usage(partition.mountpoint)
                disk_info.append({
                    'device': partition.device,
                    'mountpoint': partition.mountpoint,
                    'fstype': partition.fstype,
                    'total': usage.total,
                    'used': usage.used,
                    'free': usage.free,
                    'percent': (usage.used / usage.total) * 100
                })
            except PermissionError:
                continue
        
        self.data['hardware_info'] = {
            'cpu': cpu_info,
            'memory': memory_info,
            'disks': disk_info
        }
    
    def collect_network_info(self):
        """收集网络信息"""
        print("[3/15] 收集网络信息...")
        
        # 网络接口
        interfaces = []
        for interface, addrs in psutil.net_if_addrs().items():
            interface_info = {'name': interface, 'addresses': []}
            for addr in addrs:
                interface_info['addresses'].append({
                    'family': str(addr.family),
                    'address': addr.address,
                    'netmask': addr.netmask,
                    'broadcast': addr.broadcast
                })
            interfaces.append(interface_info)
        
        # 网络连接
        connections = []
        for conn in psutil.net_connections():
            if conn.status == 'ESTABLISHED':
                connections.append({
                    'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                    'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                    'status': conn.status,
                    'pid': conn.pid,
                    'family': str(conn.family),
                    'type': str(conn.type)
                })
        
        # 网络统计
        net_stats = psutil.net_io_counters()
        
        self.data['network_info'] = {
            'interfaces': interfaces,
            'connections': connections,
            'statistics': {
                'bytes_sent': net_stats.bytes_sent,
                'bytes_recv': net_stats.bytes_recv,
                'packets_sent': net_stats.packets_sent,
                'packets_recv': net_stats.packets_recv
            }
        }
    
    def collect_process_info(self):
        """收集进程信息"""
        print("[4/15] 收集进程信息...")
        
        processes = []
        suspicious_processes = []
        
        for proc in psutil.process_iter(['pid', 'name', 'username', 'cmdline', 'create_time', 'memory_info']):
            try:
                proc_info = {
                    'pid': proc.info['pid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': datetime.datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                    'memory_mb': proc.info['memory_info'].rss / 1024 / 1024 if proc.info['memory_info'] else 0
                }
                
                # 检查可疑进程
                suspicious_names = ['cmd.exe', 'powershell.exe', 'nc.exe', 'netcat.exe', 
                                  'psexec.exe', 'mimikatz.exe', 'procdump.exe']
                
                if proc.info['name'] and proc.info['name'].lower() in [s.lower() for s in suspicious_names]:
                    proc_info['suspicious'] = True
                    proc_info['reason'] = '可疑进程名称'
                    suspicious_processes.append(proc_info)
                else:
                    proc_info['suspicious'] = False
                
                processes.append(proc_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        self.data['process_info'] = {
            'total_processes': len(processes),
            'suspicious_count': len(suspicious_processes),
            'processes': processes,
            'suspicious_processes': suspicious_processes
        }
    
    def collect_user_info(self):
        """收集用户信息"""
        print("[5/15] 收集用户信息...")
        
        # 当前用户
        current_users = []
        for user in psutil.users():
            current_users.append({
                'name': user.name,
                'terminal': user.terminal,
                'host': user.host,
                'started': datetime.datetime.fromtimestamp(user.started).isoformat()
            })
        
        # 系统用户（通过命令获取）
        users_output = self.run_command('net user')
        admin_output = self.run_command('net localgroup Administrators')
        
        self.data['user_info'] = {
            'current_users': current_users,
            'system_users_raw': users_output,
            'administrators_raw': admin_output
        }
    
    def collect_services_info(self):
        """收集服务信息"""
        print("[6/15] 收集服务信息...")
        
        services_output = self.run_command('sc query type= service state= all')
        
        self.data['services_info'] = {
            'services_raw': services_output
        }
    
    def collect_startup_info(self):
        """收集启动项信息"""
        print("[7/15] 收集启动项信息...")
        
        startup_output = self.run_command('wmic startup get Caption,Command,Location,User')
        
        # 注册表启动项
        registry_startup = {}
        
        try:
            # HKLM Run
            with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE, 
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                hklm_run = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        hklm_run[name] = value
                        i += 1
                    except WindowsError:
                        break
                registry_startup['HKLM_Run'] = hklm_run
        except Exception as e:
            registry_startup['HKLM_Run'] = f"读取失败: {str(e)}"
        
        try:
            # HKCU Run
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, 
                              r"SOFTWARE\Microsoft\Windows\CurrentVersion\Run") as key:
                hkcu_run = {}
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(key, i)
                        hkcu_run[name] = value
                        i += 1
                    except WindowsError:
                        break
                registry_startup['HKCU_Run'] = hkcu_run
        except Exception as e:
            registry_startup['HKCU_Run'] = f"读取失败: {str(e)}"
        
        self.data['startup_info'] = {
            'startup_programs_raw': startup_output,
            'registry_startup': registry_startup
        }
    
    def collect_security_info(self):
        """收集安全信息"""
        print("[8/15] 收集安全信息...")
        
        # 防火墙状态
        firewall_output = self.run_command('netsh advfirewall show allprofiles')
        
        # 检查隐藏用户
        hidden_users_output = self.run_command(
            'reg query "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon\\SpecialAccounts\\UserList"'
        )
        
        self.data['security_info'] = {
            'firewall_status': firewall_output,
            'hidden_users_check': hidden_users_output
        }
    
    def collect_event_logs(self):
        """收集事件日志"""
        print("[9/15] 收集事件日志...")
        
        # 失败登录
        failed_logins = self.run_command(
            'wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:50 /rd:true /f:text'
        )
        
        # 成功登录
        success_logins = self.run_command(
            'wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:20 /rd:true /f:text'
        )
        
        # 系统错误
        system_errors = self.run_command(
            'wevtutil qe System /q:"*[System[(Level=2)]]" /c:20 /rd:true /f:text'
        )
        
        self.data['event_logs'] = {
            'failed_logins': failed_logins,
            'success_logins': success_logins,
            'system_errors': system_errors
        }
    
    def collect_installed_software(self):
        """收集安装的软件"""
        print("[10/15] 收集安装的软件...")
        
        software_output = self.run_command('wmic product get Name,Version,Vendor')
        
        self.data['installed_software'] = {
            'software_list': software_output
        }
    
    def collect_scheduled_tasks(self):
        """收集计划任务"""
        print("[11/15] 收集计划任务...")
        
        tasks_output = self.run_command('schtasks /query /fo LIST /v')
        
        self.data['scheduled_tasks'] = {
            'tasks_list': tasks_output
        }
    
    def collect_environment_variables(self):
        """收集环境变量"""
        print("[12/15] 收集环境变量...")
        
        env_vars = dict(os.environ)
        
        self.data['environment_variables'] = env_vars
    
    def collect_shared_resources(self):
        """收集共享资源"""
        print("[13/15] 收集共享资源...")
        
        shares_output = self.run_command('net share')
        
        self.data['shared_resources'] = {
            'shares_list': shares_output
        }
    
    def analyze_threats(self):
        """威胁分析"""
        print("[14/15] 进行威胁分析...")
        
        threats = []
        threat_score = 0
        
        # 检查可疑进程
        if self.data['process_info']['suspicious_count'] > 0:
            threats.append({
                'type': '可疑进程',
                'severity': 'High',
                'count': self.data['process_info']['suspicious_count'],
                'description': f"发现 {self.data['process_info']['suspicious_count']} 个可疑进程"
            })
            threat_score += self.data['process_info']['suspicious_count'] * 20
        
        # 检查外部连接
        external_connections = len([conn for conn in self.data['network_info']['connections'] 
                                  if not conn['remote_address'].startswith(('127.', '0.0.0.0'))])
        
        if external_connections > 10:
            threats.append({
                'type': '网络连接',
                'severity': 'Medium',
                'count': external_connections,
                'description': f"外部网络连接数量较多: {external_connections}"
            })
            threat_score += 15
        
        # 确定威胁等级
        if threat_score >= 80:
            threat_level = "严重"
        elif threat_score >= 50:
            threat_level = "高"
        elif threat_score >= 20:
            threat_level = "中"
        else:
            threat_level = "低"
        
        self.data['threat_analysis'] = {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'threats': threats,
            'external_connections': external_connections
        }
    
    def generate_summary(self):
        """生成摘要"""
        print("[15/15] 生成摘要...")
        
        summary = {
            'collection_time': datetime.datetime.now().isoformat(),
            'total_processes': self.data['process_info']['total_processes'],
            'suspicious_processes': self.data['process_info']['suspicious_count'],
            'network_connections': len(self.data['network_info']['connections']),
            'external_connections': self.data['threat_analysis']['external_connections'],
            'threat_level': self.data['threat_analysis']['threat_level'],
            'threat_score': self.data['threat_analysis']['threat_score']
        }
        
        self.data['summary'] = summary
    
    def save_results(self):
        """保存结果"""
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        
        # 同时生成文本版本摘要
        text_file = self.output_file.replace('.json', '_summary.txt')
        with open(text_file, 'w', encoding='utf-8') as f:
            f.write("Windows系统信息收集摘要\n")
            f.write("=" * 40 + "\n")
            f.write(f"收集时间: {self.data['summary']['collection_time']}\n")
            f.write(f"威胁等级: {self.data['summary']['threat_level']}\n")
            f.write(f"威胁评分: {self.data['summary']['threat_score']}/100\n")
            f.write(f"总进程数: {self.data['summary']['total_processes']}\n")
            f.write(f"可疑进程: {self.data['summary']['suspicious_processes']}\n")
            f.write(f"网络连接: {self.data['summary']['network_connections']}\n")
            f.write(f"外部连接: {self.data['summary']['external_connections']}\n")
            f.write("\n发现的威胁:\n")
            for threat in self.data['threat_analysis']['threats']:
                f.write(f"- {threat['description']} (严重性: {threat['severity']})\n")
        
        return self.output_file, text_file
    
    def run_collection(self):
        """运行完整的信息收集"""
        print("=" * 60)
        print("Windows系统信息收集器 - Python版本")
        print("=" * 60)
        print(f"开始时间: {datetime.datetime.now()}")
        print(f"输出文件: {self.output_file}")
        print("=" * 60)
        
        try:
            self.collect_system_info()
            self.collect_hardware_info()
            self.collect_network_info()
            self.collect_process_info()
            self.collect_user_info()
            self.collect_services_info()
            self.collect_startup_info()
            self.collect_security_info()
            self.collect_event_logs()
            self.collect_installed_software()
            self.collect_scheduled_tasks()
            self.collect_environment_variables()
            self.collect_shared_resources()
            self.analyze_threats()
            self.generate_summary()
            
            json_file, text_file = self.save_results()
            
            print("\n" + "=" * 60)
            print("信息收集完成！")
            print("=" * 60)
            print(f"详细报告: {json_file}")
            print(f"摘要报告: {text_file}")
            print(f"威胁等级: {self.data['summary']['threat_level']}")
            print(f"威胁评分: {self.data['summary']['threat_score']}/100")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n[错误] 收集过程中发生错误: {str(e)}")
            return False

def main():
    """主函数"""
    if platform.system() != 'Windows':
        print("[错误] 此脚本仅支持Windows系统")
        return
    
    try:
        import psutil
    except ImportError:
        print("[错误] 缺少psutil模块，请安装: pip install psutil")
        return
    
    collector = WindowsSystemCollector()
    success = collector.run_collection()
    
    if success:
        print("\n是否要查看摘要报告？")
        choice = input("输入 Y 查看，其他键退出: ").strip().upper()
        if choice == 'Y':
            text_file = collector.output_file.replace('.json', '_summary.txt')
            try:
                with open(text_file, 'r', encoding='utf-8') as f:
                    print("\n" + "=" * 60)
                    print(f.read())
                    print("=" * 60)
            except Exception as e:
                print(f"[错误] 无法读取摘要文件: {str(e)}")
    
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()