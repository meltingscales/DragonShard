#!/usr/bin/env python3
"""
Vulnerable Python Flask Application for Testing Genetic Fuzzer
Contains multiple vulnerability types: SQL Injection, XSS, Command Injection, Path Traversal, SSRF, XXE
"""

from flask import Flask, request, jsonify, render_template_string
import mysql.connector
import subprocess
import os
import requests
from lxml import etree
import re

app = Flask(__name__)

# Database connection
def get_db_connection():
    return mysql.connector.connect(
        host=os.getenv('DB_HOST', 'mysql'),
        user=os.getenv('DB_USER', 'testuser'),
        password=os.getenv('DB_PASS', 'testpass'),
        database=os.getenv('DB_NAME', 'testdb')
    )

# VULNERABILITY 1: SQL Injection
@app.route('/search', methods=['POST'])
def search():
    search_term = request.form.get('search', '')
    
    # VULNERABLE: Direct string concatenation
    query = f"SELECT * FROM users WHERE name LIKE '%{search_term}%'"
    
    try:
        conn = get_db_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute(query)  # VULNERABLE!
        results = cursor.fetchall()
        cursor.close()
        conn.close()
        return jsonify({'results': results})
    except Exception as e:
        return jsonify({'error': str(e)})  # VULNERABLE: Error disclosure

# VULNERABILITY 2: Command Injection
@app.route('/command', methods=['POST'])
def execute_command():
    command = request.form.get('command', '')
    
    # VULNERABLE: Direct command execution
    try:
        result = subprocess.check_output(command, shell=True, text=True)  # VULNERABLE!
        return jsonify({'output': result})
    except Exception as e:
        return jsonify({'error': str(e)})

# VULNERABILITY 3: Path Traversal
@app.route('/file', methods=['POST'])
def read_file():
    file_path = request.form.get('path', '')
    
    # VULNERABLE: No path validation
    full_path = os.path.join('/var/www/html', file_path)
    
    try:
        with open(full_path, 'r') as f:
            content = f.read()
        return jsonify({'content': content})
    except Exception as e:
        return jsonify({'error': str(e)})

# VULNERABILITY 4: SSRF
@app.route('/fetch', methods=['POST'])
def fetch_url():
    url = request.form.get('url', '')
    
    # VULNERABLE: No URL validation
    try:
        response = requests.get(url)  # VULNERABLE!
        return jsonify({'content': response.text})
    except Exception as e:
        return jsonify({'error': str(e)})

# VULNERABILITY 5: XXE
@app.route('/xml', methods=['POST'])
def parse_xml():
    xml_data = request.form.get('xml', '')
    
    # VULNERABLE: No XXE protection
    try:
        parser = etree.XMLParser(resolve_entities=True)  # VULNERABLE!
        root = etree.fromstring(xml_data, parser)
        return jsonify({'parsed': etree.tostring(root).decode()})
    except Exception as e:
        return jsonify({'error': str(e)})

# VULNERABILITY 6: Template Injection
@app.route('/template', methods=['POST'])
def render_template():
    template = request.form.get('template', '')
    
    # VULNERABLE: Direct template evaluation
    try:
        result = eval(template)  # VULNERABLE!
        return jsonify({'result': result})
    except Exception as e:
        return jsonify({'error': str(e)})

# VULNERABILITY 7: XSS
@app.route('/xss', methods=['POST'])
def xss():
    user_input = request.form.get('input', '')
    
    # VULNERABLE: No sanitization
    template = f"""
    <html>
        <head><title>XSS Test</title></head>
        <body>
            <h1>XSS Test</h1>
            <div>{user_input}</div>
        </body>
    </html>
    """
    
    return template

# VULNERABILITY 8: NoSQL Injection
@app.route('/nosql', methods=['POST'])
def nosql():
    username = request.form.get('username', '')
    password = request.form.get('password', '')
    
    # VULNERABLE: Direct object injection
    query = {'username': username, 'password': password}
    
    return jsonify({
        'message': f'Query: {query}',
        'vulnerable': True
    })

# Main page
@app.route('/')
def index():
    return '''
    <!DOCTYPE html>
    <html>
    <head>
        <title>Vulnerable Python App</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
            .vulnerable { background-color: #ffe6e6; }
            input, textarea { width: 100%; padding: 5px; margin: 5px 0; }
            button { padding: 10px; margin: 5px; }
        </style>
    </head>
    <body>
        <h1>Vulnerable Python Application</h1>
        <p>This application contains multiple vulnerabilities for testing the genetic fuzzer.</p>
        
        <div class="section vulnerable">
            <h2>SQL Injection Test</h2>
            <form id="sqlForm">
                <input type="text" id="sqlInput" placeholder="Search users...">
                <button type="submit">Search</button>
            </form>
            <div id="sqlResult"></div>
        </div>
        
        <div class="section vulnerable">
            <h2>Command Injection Test</h2>
            <form id="cmdForm">
                <input type="text" id="cmdInput" placeholder="Command to execute">
                <button type="submit">Execute</button>
            </form>
            <div id="cmdResult"></div>
        </div>
        
        <div class="section vulnerable">
            <h2>Path Traversal Test</h2>
            <form id="pathForm">
                <input type="text" id="pathInput" placeholder="Path to traverse">
                <button type="submit">Read File</button>
            </form>
            <div id="pathResult"></div>
        </div>
        
        <div class="section vulnerable">
            <h2>SSRF Test</h2>
            <form id="ssrfForm">
                <input type="text" id="ssrfInput" placeholder="URL to fetch">
                <button type="submit">Fetch</button>
            </form>
            <div id="ssrfResult"></div>
        </div>
        
        <div class="section vulnerable">
            <h2>XXE Test</h2>
            <form id="xxeForm">
                <textarea id="xxeInput" placeholder="XML data"></textarea>
                <button type="submit">Parse</button>
            </form>
            <div id="xxeResult"></div>
        </div>
        
        <div class="section vulnerable">
            <h2>XSS Test</h2>
            <form id="xssForm">
                <input type="text" id="xssInput" placeholder="XSS payload">
                <button type="submit">Submit</button>
            </form>
            <div id="xssResult"></div>
        </div>
        
        <script>
            // SQL Injection
            document.getElementById('sqlForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('search', document.getElementById('sqlInput').value);
                
                const response = await fetch('/search', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                document.getElementById('sqlResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            };
            
            // Command Injection
            document.getElementById('cmdForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('command', document.getElementById('cmdInput').value);
                
                const response = await fetch('/command', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                document.getElementById('cmdResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            };
            
            // Path Traversal
            document.getElementById('pathForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('path', document.getElementById('pathInput').value);
                
                const response = await fetch('/file', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                document.getElementById('pathResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            };
            
            // SSRF
            document.getElementById('ssrfForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('url', document.getElementById('ssrfInput').value);
                
                const response = await fetch('/fetch', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                document.getElementById('ssrfResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            };
            
            // XXE
            document.getElementById('xxeForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('xml', document.getElementById('xxeInput').value);
                
                const response = await fetch('/xml', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.json();
                document.getElementById('xxeResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
            };
            
            // XSS
            document.getElementById('xssForm').onsubmit = async (e) => {
                e.preventDefault();
                const formData = new FormData();
                formData.append('input', document.getElementById('xssInput').value);
                
                const response = await fetch('/xss', {
                    method: 'POST',
                    body: formData
                });
                const result = await response.text();
                document.getElementById('xssResult').innerHTML = result;
            };
        </script>
    </body>
    </html>
    '''

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000, debug=True) 