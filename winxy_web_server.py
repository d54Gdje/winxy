#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Windows紧急响应系统 - Web服务器
版本: 1.0
作者: WinXY Emergency Response Team
"""

import os
import json
import re
import datetime
import hashlib
import chardet
from flask import Flask, render_template_string, request, jsonify, send_file
from flask_cors import CORS
import logging

# 配置日志
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
logger = logging.getLogger(__name__)

app = Flask(__name__)
CORS(app)

# 配置
UPLOAD_FOLDER = 'uploads'
REPORTS_FOLDER = 'reports'
ALLOWED_EXTENSIONS = {'txt', 'log', 'csv', 'json'}

# 确保目录存在
for folder in [UPLOAD_FOLDER, REPORTS_FOLDER]:
    if not os.path.exists(folder):
        os.makedirs(folder)

def allowed_file(filename):
    """检查文件扩展名是否允许"""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def detect_encoding(file_path):
    """检测文件编码"""
    try:
        with open(file_path, 'rb') as f:
            raw_data = f.read()
            result = chardet.detect(raw_data)
            return result['encoding'] or 'utf-8'
    except:
        return 'utf-8'

def read_file_with_encoding(file_path):
    """使用检测到的编码读取文件"""
    encoding = detect_encoding(file_path)
    try:
        with open(file_path, 'r', encoding=encoding) as f:
            return f.read()
    except:
        # 如果检测的编码失败，尝试常见编码
        for enc in ['utf-8', 'gbk', 'gb2312', 'latin1']:
            try:
                with open(file_path, 'r', encoding=enc) as f:
                    return f.read()
            except:
                continue
        return ""

def analyze_processes(content):
    """分析进程信息"""
    processes = []
    suspicious_processes = []
    
    # 匹配进程信息的正则表达式
    process_patterns = [
        r'(\w+\.exe)\s+(\d+)\s+(\w+)\s+(\d+)\s+(\d+,?\d*)\s+K',  # tasklist格式
        r'Name:\s*(\w+\.exe).*?ProcessId:\s*(\d+)',  # wmic格式
        r'PID:\s*(\d+).*?Name:\s*(\w+\.exe)',  # 其他格式
    ]
    
    for pattern in process_patterns:
        matches = re.finditer(pattern, content, re.IGNORECASE | re.MULTILINE)
        for match in matches:
            if len(match.groups()) >= 2:
                process_name = match.group(1)
                pid = match.group(2)
                
                process_info = {
                    'name': process_name,
                    'pid': pid,
                    'suspicious': False,
                    'reason': ''
                }
                
                # 检查可疑进程
                suspicious_names = ['cmd.exe', 'powershell.exe', 'nc.exe', 'netcat.exe', 
                                  'psexec.exe', 'mimikatz.exe', 'procdump.exe']
                
                if process_name.lower() in [s.lower() for s in suspicious_names]:
                    process_info['suspicious'] = True
                    process_info['reason'] = '可疑进程名称'
                    suspicious_processes.append(process_info)
                
                processes.append(process_info)
    
    return {
        'total_processes': len(processes),
        'suspicious_processes': len(suspicious_processes),
        'process_list': processes[:50],  # 限制显示数量
        'suspicious_list': suspicious_processes
    }

def analyze_network_connections(content):
    """分析网络连接"""
    connections = []
    external_connections = []
    suspicious_connections = []
    
    # 匹配网络连接的正则表达式
    netstat_pattern = r'(TCP|UDP)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\d+\.\d+\.\d+\.\d+):(\d+)\s+(\w+)\s+(\d+)'
    
    matches = re.finditer(netstat_pattern, content, re.IGNORECASE)
    for match in matches:
        protocol = match.group(1)
        local_ip = match.group(2)
        local_port = match.group(3)
        remote_ip = match.group(4)
        remote_port = match.group(5)
        state = match.group(6)
        pid = match.group(7)
        
        connection_info = {
            'protocol': protocol,
            'local_ip': local_ip,
            'local_port': local_port,
            'remote_ip': remote_ip,
            'remote_port': remote_port,
            'state': state,
            'pid': pid,
            'suspicious': False,
            'reason': ''
        }
        
        # 检查是否为外部连接
        if not remote_ip.startswith(('127.', '0.0.0.0', '::1')):
            external_connections.append(connection_info)
            
            # 检查可疑端口
            suspicious_ports = ['4444', '6666', '1337', '31337', '8080', '9999']
            if remote_port in suspicious_ports:
                connection_info['suspicious'] = True
                connection_info['reason'] = f'可疑端口: {remote_port}'
                suspicious_connections.append(connection_info)
        
        connections.append(connection_info)
    
    return {
        'total_connections': len(connections),
        'external_connections': len(external_connections),
        'suspicious_connections': len(suspicious_connections),
        'connection_list': connections[:50],
        'external_list': external_connections,
        'suspicious_list': suspicious_connections
    }

def analyze_users(content):
    """分析用户信息"""
    users = []
    admin_users = []
    hidden_users = []
    
    # 匹配用户信息
    user_patterns = [
        r'User accounts for \\\\.*?\n\n(.*?)\n',  # net user格式
        r'(\w+)\s+.*?Administrator',  # 管理员用户
        r'UserList.*?(\w+)\s+REG_DWORD\s+0x0',  # 隐藏用户
    ]
    
    # 简单的用户提取
    lines = content.split('\n')
    for line in lines:
        if 'net user' in line.lower() or 'user accounts' in line.lower():
            # 提取用户名
            words = line.split()
            for word in words:
                if len(word) > 2 and word.isalnum():
                    users.append({
                        'name': word,
                        'type': 'standard',
                        'hidden': False
                    })
    
    # 检查管理员用户
    admin_pattern = r'Administrators.*?\n(.*?)\n'
    admin_matches = re.finditer(admin_pattern, content, re.IGNORECASE | re.DOTALL)
    for match in admin_matches:
        admin_section = match.group(1)
        admin_names = re.findall(r'(\w+)', admin_section)
        for name in admin_names:
            if len(name) > 2:
                admin_users.append({
                    'name': name,
                    'type': 'administrator',
                    'hidden': False
                })
    
    return {
        'total_users': len(set([u['name'] for u in users])),
        'admin_users': len(admin_users),
        'hidden_users': len(hidden_users),
        'user_list': users[:20],
        'admin_list': admin_users,
        'hidden_list': hidden_users
    }

def analyze_security_events(content):
    """分析安全事件"""
    events = {
        'failed_logins': 0,
        'successful_logins': 0,
        'system_starts': 0,
        'security_events': []
    }
    
    # 统计失败登录 (Event ID 4625)
    failed_login_pattern = r'Event ID.*?4625'
    events['failed_logins'] = len(re.findall(failed_login_pattern, content, re.IGNORECASE))
    
    # 统计成功登录 (Event ID 4624)
    success_login_pattern = r'Event ID.*?4624'
    events['successful_logins'] = len(re.findall(success_login_pattern, content, re.IGNORECASE))
    
    # 统计系统启动 (Event ID 6005)
    system_start_pattern = r'Event ID.*?6005'
    events['system_starts'] = len(re.findall(system_start_pattern, content, re.IGNORECASE))
    
    # 提取安全事件详情
    event_pattern = r'Event ID.*?(\d+).*?(\d{4}-\d{2}-\d{2}.*?\d{2}:\d{2}:\d{2})'
    event_matches = re.finditer(event_pattern, content, re.IGNORECASE)
    
    for match in event_matches:
        event_id = match.group(1)
        timestamp = match.group(2) if len(match.groups()) > 1 else 'Unknown'
        
        events['security_events'].append({
            'event_id': event_id,
            'timestamp': timestamp,
            'severity': 'High' if event_id in ['4625', '4648', '4719'] else 'Medium'
        })
    
    return events

def calculate_threat_level(analysis_results):
    """计算威胁等级"""
    score = 0
    issues = []
    
    # 检查可疑进程
    if analysis_results['processes']['suspicious_processes'] > 0:
        score += analysis_results['processes']['suspicious_processes'] * 20
        issues.append(f"发现 {analysis_results['processes']['suspicious_processes']} 个可疑进程")
    
    # 检查外部连接
    if analysis_results['network']['external_connections'] > 10:
        score += 15
        issues.append(f"外部连接数量较多 ({analysis_results['network']['external_connections']})")
    
    # 检查可疑连接
    if analysis_results['network']['suspicious_connections'] > 0:
        score += analysis_results['network']['suspicious_connections'] * 25
        issues.append(f"发现 {analysis_results['network']['suspicious_connections']} 个可疑网络连接")
    
    # 检查管理员用户
    if analysis_results['users']['admin_users'] > 3:
        score += 10
        issues.append(f"管理员用户数量较多 ({analysis_results['users']['admin_users']})")
    
    # 检查失败登录
    if analysis_results['security']['failed_logins'] > 10:
        score += analysis_results['security']['failed_logins']
        issues.append(f"失败登录尝试较多 ({analysis_results['security']['failed_logins']})")
    
    # 确定威胁等级
    if score >= 80:
        level = "严重"
        color = "red"
    elif score >= 50:
        level = "高"
        color = "orange"
    elif score >= 20:
        level = "中"
        color = "yellow"
    else:
        level = "低"
        color = "green"
    
    return {
        'score': score,
        'level': level,
        'color': color,
        'issues': issues
    }

def generate_recommendations(analysis_results, threat_assessment):
    """生成安全建议"""
    recommendations = []
    
    if analysis_results['processes']['suspicious_processes'] > 0:
        recommendations.append({
            'priority': 'High',
            'category': '进程安全',
            'description': '发现可疑进程，建议立即检查进程合法性',
            'action': '使用 tasklist /v 查看详细进程信息，必要时使用 taskkill 终止可疑进程'
        })
    
    if analysis_results['network']['suspicious_connections'] > 0:
        recommendations.append({
            'priority': 'High',
            'category': '网络安全',
            'description': '发现可疑网络连接，可能存在恶意通信',
            'action': '使用 netstat -ano 检查连接详情，考虑阻断可疑IP'
        })
    
    if analysis_results['users']['admin_users'] > 3:
        recommendations.append({
            'priority': 'Medium',
            'category': '用户管理',
            'description': '管理员账户数量较多，建议审查权限分配',
            'action': '使用 net localgroup Administrators 检查管理员列表'
        })
    
    if analysis_results['security']['failed_logins'] > 10:
        recommendations.append({
            'priority': 'Medium',
            'category': '访问控制',
            'description': '检测到多次登录失败，可能存在暴力破解攻击',
            'action': '检查事件日志，考虑启用账户锁定策略'
        })
    
    # 通用建议
    recommendations.extend([
        {
            'priority': 'Low',
            'category': '系统维护',
            'description': '定期更新系统补丁',
            'action': '运行 Windows Update 或使用 wuauclt /detectnow'
        },
        {
            'priority': 'Low',
            'category': '安全监控',
            'description': '启用Windows Defender实时保护',
            'action': '检查 Windows Security 设置'
        }
    ])
    
    return recommendations

@app.route('/')
def index():
    """主页"""
    return render_template_string(INDEX_TEMPLATE)

@app.route('/upload', methods=['POST'])
def upload_file():
    """文件上传和分析"""
    try:
        if 'file' not in request.files:
            return jsonify({'error': '没有选择文件'}), 400
        
        file = request.files['file']
        if file.filename == '':
            return jsonify({'error': '没有选择文件'}), 400
        
        if file and allowed_file(file.filename):
            # 生成安全的文件名
            timestamp = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
            filename = f"{timestamp}_{file.filename}"
            filepath = os.path.join(UPLOAD_FOLDER, filename)
            
            # 保存文件
            file.save(filepath)
            logger.info(f"文件上传成功: {filename}")
            
            # 读取文件内容
            content = read_file_with_encoding(filepath)
            if not content:
                return jsonify({'error': '无法读取文件内容或文件为空'}), 400
            
            # 执行分析
            analysis_results = {
                'file_info': {
                    'name': file.filename,
                    'size': os.path.getsize(filepath),
                    'encoding': detect_encoding(filepath),
                    'upload_time': datetime.datetime.now().isoformat()
                },
                'processes': analyze_processes(content),
                'network': analyze_network_connections(content),
                'users': analyze_users(content),
                'security': analyze_security_events(content)
            }
            
            # 威胁评估
            threat_assessment = calculate_threat_level(analysis_results)
            analysis_results['threat_assessment'] = threat_assessment
            
            # 生成建议
            recommendations = generate_recommendations(analysis_results, threat_assessment)
            analysis_results['recommendations'] = recommendations
            
            # 保存分析报告
            report_filename = f"analysis_{timestamp}.json"
            report_path = os.path.join(REPORTS_FOLDER, report_filename)
            with open(report_path, 'w', encoding='utf-8') as f:
                json.dump(analysis_results, f, ensure_ascii=False, indent=2)
            
            logger.info(f"分析完成，报告保存至: {report_filename}")
            
            return jsonify({
                'success': True,
                'analysis': analysis_results,
                'report_file': report_filename
            })
        
        else:
            return jsonify({'error': '不支持的文件类型'}), 400
    
    except Exception as e:
        logger.error(f"文件分析错误: {str(e)}")
        return jsonify({'error': f'分析失败: {str(e)}'}), 500

@app.route('/reports')
def list_reports():
    """列出所有报告"""
    try:
        reports = []
        for filename in os.listdir(REPORTS_FOLDER):
            if filename.endswith('.json'):
                filepath = os.path.join(REPORTS_FOLDER, filename)
                stat = os.stat(filepath)
                reports.append({
                    'filename': filename,
                    'size': stat.st_size,
                    'created': datetime.datetime.fromtimestamp(stat.st_ctime).isoformat()
                })
        
        reports.sort(key=lambda x: x['created'], reverse=True)
        return jsonify({'reports': reports})
    
    except Exception as e:
        logger.error(f"获取报告列表错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/reports/<filename>')
def get_report(filename):
    """获取特定报告"""
    try:
        filepath = os.path.join(REPORTS_FOLDER, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': '报告不存在'}), 404
        
        with open(filepath, 'r', encoding='utf-8') as f:
            report = json.load(f)
        
        return jsonify(report)
    
    except Exception as e:
        logger.error(f"获取报告错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

@app.route('/download/<filename>')
def download_report(filename):
    """下载报告"""
    try:
        filepath = os.path.join(REPORTS_FOLDER, filename)
        if not os.path.exists(filepath):
            return jsonify({'error': '文件不存在'}), 404
        
        return send_file(filepath, as_attachment=True)
    
    except Exception as e:
        logger.error(f"下载报告错误: {str(e)}")
        return jsonify({'error': str(e)}), 500

# HTML模板
INDEX_TEMPLATE = '''
<!DOCTYPE html>
<html lang="zh-CN">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Windows紧急响应系统 - WinXY</title>
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        
        body {
            font-family: 'Microsoft YaHei', Arial, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            background: white;
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            overflow: hidden;
        }
        
        .header {
            background: linear-gradient(135deg, #2c3e50 0%, #34495e 100%);
            color: white;
            padding: 30px;
            text-align: center;
        }
        
        .header h1 {
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        
        .header p {
            font-size: 1.2em;
            opacity: 0.9;
        }
        
        .main-content {
            padding: 40px;
        }
        
        .upload-section {
            background: #f8f9fa;
            border: 3px dashed #dee2e6;
            border-radius: 10px;
            padding: 40px;
            text-align: center;
            margin-bottom: 30px;
            transition: all 0.3s ease;
        }
        
        .upload-section:hover {
            border-color: #007bff;
            background: #e3f2fd;
        }
        
        .upload-section.dragover {
            border-color: #28a745;
            background: #d4edda;
        }
        
        .upload-icon {
            font-size: 4em;
            color: #6c757d;
            margin-bottom: 20px;
        }
        
        .upload-text {
            font-size: 1.3em;
            color: #495057;
            margin-bottom: 20px;
        }
        
        .file-input {
            display: none;
        }
        
        .upload-btn {
            background: linear-gradient(135deg, #007bff 0%, #0056b3 100%);
            color: white;
            border: none;
            padding: 15px 30px;
            border-radius: 25px;
            font-size: 1.1em;
            cursor: pointer;
            transition: all 0.3s ease;
        }
        
        .upload-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,123,255,0.3);
        }
        
        .supported-formats {
            margin-top: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }
        
        .analysis-section {
            display: none;
            margin-top: 30px;
        }
        
        .loading {
            text-align: center;
            padding: 40px;
        }
        
        .spinner {
            border: 4px solid #f3f3f3;
            border-top: 4px solid #007bff;
            border-radius: 50%;
            width: 50px;
            height: 50px;
            animation: spin 1s linear infinite;
            margin: 0 auto 20px;
        }
        
        @keyframes spin {
            0% { transform: rotate(0deg); }
            100% { transform: rotate(360deg); }
        }
        
        .results {
            display: none;
        }
        
        .threat-level {
            padding: 20px;
            border-radius: 10px;
            margin-bottom: 30px;
            text-align: center;
        }
        
        .threat-low { background: #d4edda; color: #155724; }
        .threat-medium { background: #fff3cd; color: #856404; }
        .threat-high { background: #f8d7da; color: #721c24; }
        .threat-critical { background: #f5c6cb; color: #721c24; }
        
        .stats-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(250px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .stat-card {
            background: white;
            border: 1px solid #dee2e6;
            border-radius: 10px;
            padding: 20px;
            text-align: center;
            box-shadow: 0 2px 10px rgba(0,0,0,0.1);
        }
        
        .stat-number {
            font-size: 2.5em;
            font-weight: bold;
            color: #007bff;
            margin-bottom: 10px;
        }
        
        .stat-label {
            color: #6c757d;
            font-size: 1.1em;
        }
        
        .details-section {
            margin-top: 30px;
        }
        
        .details-tabs {
            display: flex;
            border-bottom: 2px solid #dee2e6;
            margin-bottom: 20px;
        }
        
        .tab-btn {
            background: none;
            border: none;
            padding: 15px 25px;
            cursor: pointer;
            font-size: 1.1em;
            color: #6c757d;
            border-bottom: 3px solid transparent;
            transition: all 0.3s ease;
        }
        
        .tab-btn.active {
            color: #007bff;
            border-bottom-color: #007bff;
        }
        
        .tab-content {
            display: none;
        }
        
        .tab-content.active {
            display: block;
        }
        
        .data-table {
            width: 100%;
            border-collapse: collapse;
            margin-top: 20px;
        }
        
        .data-table th,
        .data-table td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #dee2e6;
        }
        
        .data-table th {
            background: #f8f9fa;
            font-weight: bold;
            color: #495057;
        }
        
        .suspicious {
            background: #f8d7da !important;
            color: #721c24;
        }
        
        .recommendations {
            background: #e3f2fd;
            border-radius: 10px;
            padding: 20px;
            margin-top: 30px;
        }
        
        .recommendation-item {
            background: white;
            border-radius: 8px;
            padding: 15px;
            margin-bottom: 15px;
            border-left: 4px solid #007bff;
        }
        
        .recommendation-priority {
            font-weight: bold;
            margin-bottom: 5px;
        }
        
        .priority-high { color: #dc3545; }
        .priority-medium { color: #ffc107; }
        .priority-low { color: #28a745; }
        
        .error-message {
            background: #f8d7da;
            color: #721c24;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            text-align: center;
        }
        
        .success-message {
            background: #d4edda;
            color: #155724;
            padding: 20px;
            border-radius: 10px;
            margin-top: 20px;
            text-align: center;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>🛡️ Windows紧急响应系统</h1>
            <p>WinXY Emergency Response System - 专业的Windows安全分析平台</p>
        </div>
        
        <div class="main-content">
            <div class="upload-section" id="uploadSection">
                <div class="upload-icon">📁</div>
                <div class="upload-text">拖拽文件到此处或点击选择文件</div>
                <input type="file" id="fileInput" class="file-input" accept=".txt,.log,.csv,.json">
                <button class="upload-btn" onclick="document.getElementById('fileInput').click()">
                    选择文件
                </button>
                <div class="supported-formats">
                    支持格式: .txt, .log, .csv, .json
                </div>
            </div>
            
            <div class="analysis-section" id="analysisSection">
                <div class="loading" id="loadingDiv">
                    <div class="spinner"></div>
                    <div>正在分析文件，请稍候...</div>
                </div>
                
                <div class="results" id="resultsDiv">
                    <!-- 分析结果将在这里显示 -->
                </div>
            </div>
        </div>
    </div>

    <script>
        // 文件上传和拖拽功能
        const uploadSection = document.getElementById('uploadSection');
        const fileInput = document.getElementById('fileInput');
        const analysisSection = document.getElementById('analysisSection');
        const loadingDiv = document.getElementById('loadingDiv');
        const resultsDiv = document.getElementById('resultsDiv');
        
        // 拖拽事件
        uploadSection.addEventListener('dragover', (e) => {
            e.preventDefault();
            uploadSection.classList.add('dragover');
        });
        
        uploadSection.addEventListener('dragleave', () => {
            uploadSection.classList.remove('dragover');
        });
        
        uploadSection.addEventListener('drop', (e) => {
            e.preventDefault();
            uploadSection.classList.remove('dragover');
            const files = e.dataTransfer.files;
            if (files.length > 0) {
                handleFile(files[0]);
            }
        });
        
        // 文件选择事件
        fileInput.addEventListener('change', (e) => {
            if (e.target.files.length > 0) {
                handleFile(e.target.files[0]);
            }
        });
        
        // 处理文件上传
        function handleFile(file) {
            const formData = new FormData();
            formData.append('file', file);
            
            // 显示加载界面
            analysisSection.style.display = 'block';
            loadingDiv.style.display = 'block';
            resultsDiv.style.display = 'none';
            
            // 上传文件
            fetch('/upload', {
                method: 'POST',
                body: formData
            })
            .then(response => response.json())
            .then(data => {
                loadingDiv.style.display = 'none';
                if (data.success) {
                    displayResults(data.analysis);
                } else {
                    displayError(data.error);
                }
            })
            .catch(error => {
                loadingDiv.style.display = 'none';
                displayError('上传失败: ' + error.message);
            });
        }
        
        // 显示分析结果
        function displayResults(analysis) {
            const threat = analysis.threat_assessment;
            const threatClass = `threat-${threat.level.toLowerCase()}`;
            
            resultsDiv.innerHTML = `
                <div class="threat-level ${threatClass}">
                    <h2>威胁等级: ${threat.level}</h2>
                    <p>安全评分: ${threat.score}/100</p>
                    <p>发现问题: ${threat.issues.length} 个</p>
                </div>
                
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${analysis.processes.total_processes}</div>
                        <div class="stat-label">总进程数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${analysis.processes.suspicious_processes}</div>
                        <div class="stat-label">可疑进程</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${analysis.network.external_connections}</div>
                        <div class="stat-label">外部连接</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${analysis.users.total_users}</div>
                        <div class="stat-label">用户账户</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${analysis.users.admin_users}</div>
                        <div class="stat-label">管理员用户</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${analysis.security.failed_logins}</div>
                        <div class="stat-label">失败登录</div>
                    </div>
                </div>
                
                <div class="details-section">
                    <div class="details-tabs">
                        <button class="tab-btn active" onclick="showTab('processes')">进程详情</button>
                        <button class="tab-btn" onclick="showTab('network')">网络连接</button>
                        <button class="tab-btn" onclick="showTab('users')">用户信息</button>
                        <button class="tab-btn" onclick="showTab('security')">安全事件</button>
                    </div>
                    
                    <div id="processes-tab" class="tab-content active">
                        <h3>进程分析</h3>
                        ${generateProcessTable(analysis.processes)}
                    </div>
                    
                    <div id="network-tab" class="tab-content">
                        <h3>网络连接分析</h3>
                        ${generateNetworkTable(analysis.network)}
                    </div>
                    
                    <div id="users-tab" class="tab-content">
                        <h3>用户账户分析</h3>
                        ${generateUserTable(analysis.users)}
                    </div>
                    
                    <div id="security-tab" class="tab-content">
                        <h3>安全事件分析</h3>
                        ${generateSecurityTable(analysis.security)}
                    </div>
                </div>
                
                <div class="recommendations">
                    <h3>🔧 安全建议</h3>
                    ${generateRecommendations(analysis.recommendations)}
                </div>
            `;
            
            resultsDiv.style.display = 'block';
        }
        
        // 生成进程表格
        function generateProcessTable(processes) {
            let html = '<table class="data-table"><thead><tr><th>进程名</th><th>PID</th><th>状态</th><th>风险说明</th></tr></thead><tbody>';
            
            processes.process_list.forEach(process => {
                const rowClass = process.suspicious ? 'suspicious' : '';
                html += `<tr class="${rowClass}">
                    <td>${process.name}</td>
                    <td>${process.pid}</td>
                    <td>${process.suspicious ? '⚠️ 可疑' : '✅ 正常'}</td>
                    <td>${process.reason || '-'}</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            return html;
        }
        
        // 生成网络连接表格
        function generateNetworkTable(network) {
            let html = '<table class="data-table"><thead><tr><th>协议</th><th>本地地址</th><th>远程地址</th><th>状态</th><th>PID</th><th>风险说明</th></tr></thead><tbody>';
            
            network.external_list.forEach(conn => {
                const rowClass = conn.suspicious ? 'suspicious' : '';
                html += `<tr class="${rowClass}">
                    <td>${conn.protocol}</td>
                    <td>${conn.local_ip}:${conn.local_port}</td>
                    <td>${conn.remote_ip}:${conn.remote_port}</td>
                    <td>${conn.state}</td>
                    <td>${conn.pid}</td>
                    <td>${conn.reason || '-'}</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            return html;
        }
        
        // 生成用户表格
        function generateUserTable(users) {
            let html = '<table class="data-table"><thead><tr><th>用户名</th><th>类型</th><th>状态</th></tr></thead><tbody>';
            
            users.user_list.forEach(user => {
                html += `<tr>
                    <td>${user.name}</td>
                    <td>${user.type === 'administrator' ? '👑 管理员' : '👤 普通用户'}</td>
                    <td>${user.hidden ? '🔒 隐藏' : '👁️ 可见'}</td>
                </tr>`;
            });
            
            html += '</tbody></table>';
            return html;
        }
        
        // 生成安全事件表格
        function generateSecurityTable(security) {
            let html = `
                <div class="stats-grid">
                    <div class="stat-card">
                        <div class="stat-number">${security.failed_logins}</div>
                        <div class="stat-label">失败登录次数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${security.successful_logins}</div>
                        <div class="stat-label">成功登录次数</div>
                    </div>
                    <div class="stat-card">
                        <div class="stat-number">${security.system_starts}</div>
                        <div class="stat-label">系统启动次数</div>
                    </div>
                </div>
            `;
            
            if (security.security_events.length > 0) {
                html += '<table class="data-table"><thead><tr><th>事件ID</th><th>时间</th><th>严重性</th></tr></thead><tbody>';
                
                security.security_events.slice(0, 20).forEach(event => {
                    html += `<tr>
                        <td>${event.event_id}</td>
                        <td>${event.timestamp}</td>
                        <td>${event.severity}</td>
                    </tr>`;
                });
                
                html += '</tbody></table>';
            }
            
            return html;
        }
        
        // 生成建议
        function generateRecommendations(recommendations) {
            let html = '';
            
            recommendations.forEach(rec => {
                const priorityClass = `priority-${rec.priority.toLowerCase()}`;
                html += `
                    <div class="recommendation-item">
                        <div class="recommendation-priority ${priorityClass}">
                            ${rec.priority === 'High' ? '🔴' : rec.priority === 'Medium' ? '🟡' : '🟢'} 
                            ${rec.priority} - ${rec.category}
                        </div>
                        <div><strong>问题:</strong> ${rec.description}</div>
                        <div><strong>建议:</strong> ${rec.action}</div>
                    </div>
                `;
            });
            
            return html;
        }
        
        // 显示错误信息
        function displayError(message) {
            resultsDiv.innerHTML = `<div class="error-message">❌ ${message}</div>`;
            resultsDiv.style.display = 'block';
        }
        
        // 切换标签页
        function showTab(tabName) {
            // 隐藏所有标签内容
            document.querySelectorAll('.tab-content').forEach(tab => {
                tab.classList.remove('active');
            });
            
            // 移除所有按钮的活动状态
            document.querySelectorAll('.tab-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            
            // 显示选中的标签内容
            document.getElementById(tabName + '-tab').classList.add('active');
            
            // 激活对应的按钮
            event.target.classList.add('active');
        }
    </script>
</body>
</html>
'''

if __name__ == '__main__':
    print("=" * 60)
    print("Windows紧急响应系统 - Web服务器")
    print("=" * 60)
    print(f"服务器启动中...")
    print(f"Web界面地址: http://localhost:12000")
    print(f"上传目录: {UPLOAD_FOLDER}")
    print(f"报告目录: {REPORTS_FOLDER}")
    print("按 Ctrl+C 停止服务器")
    print("=" * 60)
    
    try:
        app.run(host='0.0.0.0', port=12000, debug=False)
    except KeyboardInterrupt:
        print("\n服务器已停止")
    except Exception as e:
        print(f"服务器启动失败: {e}")
        input("按回车键退出...")