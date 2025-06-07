#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows进程分析脚本 (Python版本)
版本: 1.0
用途: 深度分析系统进程和可疑活动
"""

import os
import sys
import json
import psutil
import datetime
import hashlib
import subprocess
from pathlib import Path

class WindowsProcessAnalyzer:
    def __init__(self):
        self.timestamp = datetime.datetime.now().strftime('%Y-%m-%d_%H-%M-%S')
        self.output_file = f"process_analysis_python_{self.timestamp}.json"
        self.text_file = f"process_analysis_python_{self.timestamp}.txt"
        
        # 可疑进程名称列表
        self.suspicious_names = [
            'cmd.exe', 'powershell.exe', 'nc.exe', 'netcat.exe',
            'psexec.exe', 'mimikatz.exe', 'procdump.exe', 'wce.exe',
            'fgdump.exe', 'pwdump.exe', 'gsecdump.exe', 'cachedump.exe',
            'lsadump.exe', 'pwdumpx.exe', 'servpw.exe', 'htool.exe'
        ]
        
        # 可疑路径
        self.suspicious_paths = [
            'temp', 'tmp', 'appdata\\local\\temp', 'windows\\temp',
            'programdata', 'users\\public', 'recycle'
        ]
        
        self.data = {
            'analysis_info': {
                'timestamp': self.timestamp,
                'tool': 'Python进程分析器',
                'version': '1.0'
            }
        }
    
    def get_process_hash(self, exe_path):
        """计算进程文件的哈希值"""
        try:
            if os.path.exists(exe_path):
                with open(exe_path, 'rb') as f:
                    content = f.read()
                    return hashlib.md5(content).hexdigest()
        except:
            pass
        return None
    
    def is_suspicious_process(self, proc_info):
        """判断进程是否可疑"""
        suspicious_reasons = []
        
        # 检查进程名称
        if proc_info['name'] and proc_info['name'].lower() in [s.lower() for s in self.suspicious_names]:
            suspicious_reasons.append(f"可疑进程名称: {proc_info['name']}")
        
        # 检查进程路径
        if proc_info['exe_path']:
            path_lower = proc_info['exe_path'].lower()
            for sus_path in self.suspicious_paths:
                if sus_path in path_lower:
                    suspicious_reasons.append(f"可疑路径: {proc_info['exe_path']}")
                    break
        
        # 检查内存使用异常
        if proc_info['memory_mb'] > 1000:  # 超过1GB内存
            suspicious_reasons.append(f"内存使用异常: {proc_info['memory_mb']:.2f}MB")
        
        # 检查CPU使用异常
        if proc_info['cpu_percent'] > 80:  # CPU使用率超过80%
            suspicious_reasons.append(f"CPU使用异常: {proc_info['cpu_percent']:.2f}%")
        
        # 检查无父进程的情况（可能是注入进程）
        if proc_info['ppid'] == 0 and proc_info['pid'] != 0:
            suspicious_reasons.append("无父进程（可能是进程注入）")
        
        return suspicious_reasons
    
    def analyze_processes(self):
        """分析所有进程"""
        print("[1/8] 收集进程信息...")
        
        processes = []
        suspicious_processes = []
        high_memory_processes = []
        high_cpu_processes = []
        
        for proc in psutil.process_iter(['pid', 'ppid', 'name', 'username', 'cmdline', 
                                       'create_time', 'memory_info', 'cpu_percent', 'exe']):
            try:
                # 获取CPU使用率（需要短暂等待）
                cpu_percent = proc.cpu_percent(interval=0.1)
                
                proc_info = {
                    'pid': proc.info['pid'],
                    'ppid': proc.info['ppid'],
                    'name': proc.info['name'],
                    'username': proc.info['username'],
                    'cmdline': ' '.join(proc.info['cmdline']) if proc.info['cmdline'] else '',
                    'create_time': datetime.datetime.fromtimestamp(proc.info['create_time']).isoformat(),
                    'memory_mb': proc.info['memory_info'].rss / 1024 / 1024 if proc.info['memory_info'] else 0,
                    'cpu_percent': cpu_percent,
                    'exe_path': proc.info['exe'],
                    'file_hash': None,
                    'suspicious': False,
                    'suspicious_reasons': []
                }
                
                # 计算文件哈希
                if proc_info['exe_path']:
                    proc_info['file_hash'] = self.get_process_hash(proc_info['exe_path'])
                
                # 检查是否可疑
                suspicious_reasons = self.is_suspicious_process(proc_info)
                if suspicious_reasons:
                    proc_info['suspicious'] = True
                    proc_info['suspicious_reasons'] = suspicious_reasons
                    suspicious_processes.append(proc_info)
                
                # 高内存使用进程
                if proc_info['memory_mb'] > 500:
                    high_memory_processes.append(proc_info)
                
                # 高CPU使用进程
                if proc_info['cpu_percent'] > 50:
                    high_cpu_processes.append(proc_info)
                
                processes.append(proc_info)
                
            except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
                continue
        
        # 按内存使用排序
        high_memory_processes.sort(key=lambda x: x['memory_mb'], reverse=True)
        high_cpu_processes.sort(key=lambda x: x['cpu_percent'], reverse=True)
        
        self.data['process_analysis'] = {
            'total_processes': len(processes),
            'suspicious_count': len(suspicious_processes),
            'high_memory_count': len(high_memory_processes),
            'high_cpu_count': len(high_cpu_processes),
            'processes': processes,
            'suspicious_processes': suspicious_processes,
            'high_memory_processes': high_memory_processes[:20],  # 前20个
            'high_cpu_processes': high_cpu_processes[:20]
        }
    
    def analyze_process_tree(self):
        """分析进程树结构"""
        print("[2/8] 分析进程树结构...")
        
        process_tree = {}
        orphan_processes = []
        
        # 构建进程树
        for proc_info in self.data['process_analysis']['processes']:
            pid = proc_info['pid']
            ppid = proc_info['ppid']
            
            if ppid not in process_tree:
                process_tree[ppid] = []
            process_tree[ppid].append(proc_info)
            
            # 检查孤儿进程
            if ppid != 0:
                parent_exists = any(p['pid'] == ppid for p in self.data['process_analysis']['processes'])
                if not parent_exists:
                    orphan_processes.append(proc_info)
        
        self.data['process_tree'] = {
            'tree_structure': process_tree,
            'orphan_processes': orphan_processes,
            'orphan_count': len(orphan_processes)
        }
    
    def analyze_network_processes(self):
        """分析有网络连接的进程"""
        print("[3/8] 分析网络连接进程...")
        
        network_processes = {}
        suspicious_connections = []
        
        try:
            for conn in psutil.net_connections():
                if conn.pid and conn.status == 'ESTABLISHED':
                    if conn.pid not in network_processes:
                        # 获取进程信息
                        try:
                            proc = psutil.Process(conn.pid)
                            network_processes[conn.pid] = {
                                'pid': conn.pid,
                                'name': proc.name(),
                                'exe_path': proc.exe(),
                                'connections': []
                            }
                        except:
                            network_processes[conn.pid] = {
                                'pid': conn.pid,
                                'name': 'Unknown',
                                'exe_path': 'Unknown',
                                'connections': []
                            }
                    
                    conn_info = {
                        'local_address': f"{conn.laddr.ip}:{conn.laddr.port}" if conn.laddr else None,
                        'remote_address': f"{conn.raddr.ip}:{conn.raddr.port}" if conn.raddr else None,
                        'status': conn.status,
                        'family': str(conn.family),
                        'type': str(conn.type)
                    }
                    
                    network_processes[conn.pid]['connections'].append(conn_info)
                    
                    # 检查可疑连接
                    if conn.raddr and not conn.raddr.ip.startswith(('127.', '0.0.0.0')):
                        # 检查可疑端口
                        suspicious_ports = [4444, 6666, 1337, 31337, 8080, 9999, 12345, 54321]
                        if conn.raddr.port in suspicious_ports:
                            suspicious_connections.append({
                                'pid': conn.pid,
                                'process_name': network_processes[conn.pid]['name'],
                                'connection': conn_info,
                                'reason': f'可疑端口: {conn.raddr.port}'
                            })
        
        except Exception as e:
            print(f"分析网络连接时出错: {e}")
        
        self.data['network_analysis'] = {
            'network_processes': list(network_processes.values()),
            'network_process_count': len(network_processes),
            'suspicious_connections': suspicious_connections,
            'suspicious_connection_count': len(suspicious_connections)
        }
    
    def analyze_startup_processes(self):
        """分析启动时运行的进程"""
        print("[4/8] 分析启动进程...")
        
        # 获取系统启动时间
        boot_time = psutil.boot_time()
        boot_datetime = datetime.datetime.fromtimestamp(boot_time)
        
        startup_processes = []
        recent_processes = []
        
        for proc_info in self.data['process_analysis']['processes']:
            create_time = datetime.datetime.fromisoformat(proc_info['create_time'])
            
            # 启动后5分钟内创建的进程
            if (create_time - boot_datetime).total_seconds() < 300:
                startup_processes.append(proc_info)
            
            # 最近1小时内创建的进程
            if (datetime.datetime.now() - create_time).total_seconds() < 3600:
                recent_processes.append(proc_info)
        
        self.data['startup_analysis'] = {
            'boot_time': boot_datetime.isoformat(),
            'startup_processes': startup_processes,
            'startup_process_count': len(startup_processes),
            'recent_processes': recent_processes,
            'recent_process_count': len(recent_processes)
        }
    
    def analyze_process_privileges(self):
        """分析进程权限"""
        print("[5/8] 分析进程权限...")
        
        elevated_processes = []
        system_processes = []
        
        for proc_info in self.data['process_analysis']['processes']:
            username = proc_info['username']
            
            if username:
                if 'SYSTEM' in username.upper():
                    system_processes.append(proc_info)
                elif 'ADMINISTRATOR' in username.upper() or 'ADMIN' in username.upper():
                    elevated_processes.append(proc_info)
        
        self.data['privilege_analysis'] = {
            'elevated_processes': elevated_processes,
            'elevated_count': len(elevated_processes),
            'system_processes': system_processes,
            'system_count': len(system_processes)
        }
    
    def analyze_process_modules(self):
        """分析进程加载的模块"""
        print("[6/8] 分析进程模块...")
        
        suspicious_modules = []
        unsigned_modules = []
        
        # 可疑DLL名称
        suspicious_dlls = [
            'inject', 'hook', 'keylog', 'stealth', 'hide', 'bypass',
            'exploit', 'payload', 'shell', 'backdoor'
        ]
        
        try:
            # 只分析可疑进程的模块
            for proc_info in self.data['process_analysis']['suspicious_processes']:
                try:
                    proc = psutil.Process(proc_info['pid'])
                    
                    # 使用wmic获取模块信息（更详细）
                    cmd = f'wmic process where "ProcessId={proc_info["pid"]}" get ExecutablePath'
                    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
                    
                    if result.returncode == 0:
                        proc_info['wmic_info'] = result.stdout.strip()
                
                except:
                    continue
        
        except Exception as e:
            print(f"分析进程模块时出错: {e}")
        
        self.data['module_analysis'] = {
            'suspicious_modules': suspicious_modules,
            'unsigned_modules': unsigned_modules
        }
    
    def generate_threat_assessment(self):
        """生成威胁评估"""
        print("[7/8] 生成威胁评估...")
        
        threat_score = 0
        threats = []
        
        # 可疑进程评分
        suspicious_count = self.data['process_analysis']['suspicious_count']
        if suspicious_count > 0:
            threat_score += suspicious_count * 25
            threats.append(f"发现 {suspicious_count} 个可疑进程")
        
        # 可疑网络连接评分
        suspicious_conn_count = self.data['network_analysis']['suspicious_connection_count']
        if suspicious_conn_count > 0:
            threat_score += suspicious_conn_count * 30
            threats.append(f"发现 {suspicious_conn_count} 个可疑网络连接")
        
        # 孤儿进程评分
        orphan_count = self.data['process_tree']['orphan_count']
        if orphan_count > 5:
            threat_score += 15
            threats.append(f"发现 {orphan_count} 个孤儿进程")
        
        # 高内存使用评分
        high_memory_count = self.data['process_analysis']['high_memory_count']
        if high_memory_count > 10:
            threat_score += 10
            threats.append(f"发现 {high_memory_count} 个高内存使用进程")
        
        # 确定威胁等级
        if threat_score >= 80:
            threat_level = "严重"
        elif threat_score >= 50:
            threat_level = "高"
        elif threat_score >= 20:
            threat_level = "中"
        else:
            threat_level = "低"
        
        self.data['threat_assessment'] = {
            'threat_level': threat_level,
            'threat_score': threat_score,
            'threats': threats,
            'recommendations': self.generate_recommendations(threats)
        }
    
    def generate_recommendations(self, threats):
        """生成安全建议"""
        recommendations = []
        
        if any('可疑进程' in threat for threat in threats):
            recommendations.append({
                'priority': 'High',
                'category': '进程安全',
                'description': '立即检查可疑进程的合法性',
                'action': '使用 tasklist /v 查看详细信息，必要时使用 taskkill 终止'
            })
        
        if any('可疑网络连接' in threat for threat in threats):
            recommendations.append({
                'priority': 'High',
                'category': '网络安全',
                'description': '检查可疑网络连接',
                'action': '使用 netstat -ano 查看连接详情，考虑阻断可疑IP'
            })
        
        if any('孤儿进程' in threat for threat in threats):
            recommendations.append({
                'priority': 'Medium',
                'category': '进程管理',
                'description': '检查孤儿进程的来源',
                'action': '分析进程创建时间和路径，确认合法性'
            })
        
        # 通用建议
        recommendations.extend([
            {
                'priority': 'Low',
                'category': '系统维护',
                'description': '定期监控进程活动',
                'action': '使用任务管理器或进程监控工具定期检查'
            },
            {
                'priority': 'Low',
                'category': '安全防护',
                'description': '启用实时防护',
                'action': '确保防病毒软件实时监控功能已启用'
            }
        ])
        
        return recommendations
    
    def save_results(self):
        """保存分析结果"""
        print("[8/8] 保存分析结果...")
        
        # 保存JSON格式
        with open(self.output_file, 'w', encoding='utf-8') as f:
            json.dump(self.data, f, ensure_ascii=False, indent=2)
        
        # 生成文本格式摘要
        with open(self.text_file, 'w', encoding='utf-8') as f:
            f.write("Windows进程分析报告\n")
            f.write("=" * 50 + "\n")
            f.write(f"分析时间: {self.data['analysis_info']['timestamp']}\n")
            f.write(f"分析工具: {self.data['analysis_info']['tool']}\n\n")
            
            # 基本统计
            f.write("基本统计:\n")
            f.write(f"- 总进程数: {self.data['process_analysis']['total_processes']}\n")
            f.write(f"- 可疑进程数: {self.data['process_analysis']['suspicious_count']}\n")
            f.write(f"- 高内存使用进程: {self.data['process_analysis']['high_memory_count']}\n")
            f.write(f"- 高CPU使用进程: {self.data['process_analysis']['high_cpu_count']}\n")
            f.write(f"- 网络连接进程: {self.data['network_analysis']['network_process_count']}\n")
            f.write(f"- 可疑网络连接: {self.data['network_analysis']['suspicious_connection_count']}\n\n")
            
            # 威胁评估
            f.write("威胁评估:\n")
            f.write(f"- 威胁等级: {self.data['threat_assessment']['threat_level']}\n")
            f.write(f"- 威胁评分: {self.data['threat_assessment']['threat_score']}/100\n")
            f.write(f"- 发现威胁: {len(self.data['threat_assessment']['threats'])} 个\n\n")
            
            if self.data['threat_assessment']['threats']:
                f.write("发现的威胁:\n")
                for threat in self.data['threat_assessment']['threats']:
                    f.write(f"- {threat}\n")
                f.write("\n")
            
            # 可疑进程详情
            if self.data['process_analysis']['suspicious_processes']:
                f.write("可疑进程详情:\n")
                for proc in self.data['process_analysis']['suspicious_processes']:
                    f.write(f"- {proc['name']} (PID: {proc['pid']})\n")
                    f.write(f"  路径: {proc['exe_path']}\n")
                    f.write(f"  用户: {proc['username']}\n")
                    f.write(f"  内存: {proc['memory_mb']:.2f}MB\n")
                    f.write(f"  可疑原因: {', '.join(proc['suspicious_reasons'])}\n\n")
            
            # 安全建议
            f.write("安全建议:\n")
            for rec in self.data['threat_assessment']['recommendations']:
                f.write(f"- [{rec['priority']}] {rec['description']}\n")
                f.write(f"  操作: {rec['action']}\n\n")
        
        return self.output_file, self.text_file
    
    def run_analysis(self):
        """运行完整的进程分析"""
        print("=" * 60)
        print("Windows进程分析器 - Python版本")
        print("=" * 60)
        print(f"开始时间: {datetime.datetime.now()}")
        print(f"输出文件: {self.output_file}")
        print("=" * 60)
        
        try:
            self.analyze_processes()
            self.analyze_process_tree()
            self.analyze_network_processes()
            self.analyze_startup_processes()
            self.analyze_process_privileges()
            self.analyze_process_modules()
            self.generate_threat_assessment()
            
            json_file, text_file = self.save_results()
            
            print("\n" + "=" * 60)
            print("进程分析完成！")
            print("=" * 60)
            print(f"详细报告: {json_file}")
            print(f"摘要报告: {text_file}")
            print(f"威胁等级: {self.data['threat_assessment']['threat_level']}")
            print(f"威胁评分: {self.data['threat_assessment']['threat_score']}/100")
            print(f"可疑进程: {self.data['process_analysis']['suspicious_count']} 个")
            print("=" * 60)
            
            return True
            
        except Exception as e:
            print(f"\n[错误] 分析过程中发生错误: {str(e)}")
            return False

def main():
    """主函数"""
    if os.name != 'nt':
        print("[错误] 此脚本仅支持Windows系统")
        return
    
    try:
        import psutil
    except ImportError:
        print("[错误] 缺少psutil模块，请安装: pip install psutil")
        return
    
    analyzer = WindowsProcessAnalyzer()
    success = analyzer.run_analysis()
    
    if success:
        print("\n是否要查看摘要报告？")
        choice = input("输入 Y 查看，其他键退出: ").strip().upper()
        if choice == 'Y':
            try:
                with open(analyzer.text_file, 'r', encoding='utf-8') as f:
                    print("\n" + "=" * 60)
                    print(f.read())
                    print("=" * 60)
            except Exception as e:
                print(f"[错误] 无法读取摘要文件: {str(e)}")
    
    input("\n按回车键退出...")

if __name__ == "__main__":
    main()