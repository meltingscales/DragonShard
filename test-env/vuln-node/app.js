const express = require('express');
const bodyParser = require('body-parser');
const mysql = require('mysql2');
const { exec } = require('child_process');
const path = require('path');
const fs = require('fs');

const app = express();
const port = 3000;

// Middleware
app.use(bodyParser.urlencoded({ extended: true }));
app.use(bodyParser.json());
app.use(express.static('public'));

// Database connection
const db = mysql.createConnection({
    host: process.env.DB_HOST || 'mysql',
    user: process.env.DB_USER || 'testuser',
    password: process.env.DB_PASS || 'testpass',
    database: process.env.DB_NAME || 'testdb'
});

// VULNERABILITY 1: SQL Injection
app.post('/search', (req, res) => {
    const search = req.body.search || '';
    
    // VULNERABLE: Direct string concatenation
    const query = `SELECT * FROM users WHERE name LIKE '%${search}%'`;
    
    db.query(query, (err, results) => {
        if (err) {
            res.json({ error: err.message }); // VULNERABLE: Error disclosure
        } else {
            res.json({ results });
        }
    });
});

// VULNERABILITY 2: NoSQL Injection
app.post('/nosql', (req, res) => {
    const username = req.body.username || '';
    const password = req.body.password || '';
    
    // VULNERABLE: Direct object injection
    const query = { username: username, password: password };
    
    // Simulate NoSQL injection
    res.json({ 
        message: `Query: ${JSON.stringify(query)}`,
        vulnerable: true 
    });
});

// VULNERABILITY 3: Command Injection
app.post('/command', (req, res) => {
    const cmd = req.body.command || '';
    
    // VULNERABLE: Direct command execution
    exec(`ping -c 1 ${cmd}`, (error, stdout, stderr) => {
        if (error) {
            res.json({ error: error.message });
        } else {
            res.json({ output: stdout });
        }
    });
});

// VULNERABILITY 4: Path Traversal
app.get('/file', (req, res) => {
    const filePath = req.query.path || '';
    
    // VULNERABLE: No path validation
    const fullPath = path.join('/var/www/html', filePath);
    
    fs.readFile(fullPath, 'utf8', (err, data) => {
        if (err) {
            res.json({ error: err.message });
        } else {
            res.json({ content: data });
        }
    });
});

// VULNERABILITY 5: Template Injection
app.post('/template', (req, res) => {
    const template = req.body.template || '';
    
    // VULNERABLE: Direct template evaluation
    try {
        const result = eval(template); // VULNERABLE!
        res.json({ result });
    } catch (error) {
        res.json({ error: error.message });
    }
});

// VULNERABILITY 6: SSRF
app.get('/fetch', (req, res) => {
    const url = req.query.url || '';
    
    // VULNERABLE: No URL validation
    const https = require('https');
    https.get(url, (resp) => {
        let data = '';
        resp.on('data', (chunk) => {
            data += chunk;
        });
        resp.on('end', () => {
            res.json({ content: data });
        });
    }).on('error', (err) => {
        res.json({ error: err.message });
    });
});

// VULNERABILITY 7: XSS
app.post('/xss', (req, res) => {
    const input = req.body.input || '';
    
    // VULNERABLE: No sanitization
    const html = `
        <html>
            <body>
                <h1>XSS Test</h1>
                <div>${input}</div>
            </body>
        </html>
    `;
    
    res.send(html);
});

// VULNERABILITY 8: XXE
app.post('/xml', (req, res) => {
    const xml = req.body.xml || '';
    
    // VULNERABLE: No XXE protection
    const xml2js = require('xml2js');
    const parser = new xml2js.Parser();
    
    parser.parseString(xml, (err, result) => {
        if (err) {
            res.json({ error: err.message });
        } else {
            res.json({ parsed: result });
        }
    });
});

// Main page
app.get('/', (req, res) => {
    res.send(`
        <!DOCTYPE html>
        <html>
        <head>
            <title>Vulnerable Node.js App</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
                .vulnerable { background-color: #ffe6e6; }
                input, textarea { width: 100%; padding: 5px; margin: 5px 0; }
                button { padding: 10px; margin: 5px; }
            </style>
        </head>
        <body>
            <h1>Vulnerable Node.js Application</h1>
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
                    const response = await fetch('/search', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ search: document.getElementById('sqlInput').value })
                    });
                    const result = await response.json();
                    document.getElementById('sqlResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                };
                
                // Command Injection
                document.getElementById('cmdForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const response = await fetch('/command', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ command: document.getElementById('cmdInput').value })
                    });
                    const result = await response.json();
                    document.getElementById('cmdResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                };
                
                // Path Traversal
                document.getElementById('pathForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const response = await fetch('/file?path=' + encodeURIComponent(document.getElementById('pathInput').value));
                    const result = await response.json();
                    document.getElementById('pathResult').innerHTML = '<pre>' + JSON.stringify(result, null, 2) + '</pre>';
                };
                
                // XSS
                document.getElementById('xssForm').onsubmit = async (e) => {
                    e.preventDefault();
                    const response = await fetch('/xss', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ input: document.getElementById('xssInput').value })
                    });
                    const result = await response.text();
                    document.getElementById('xssResult').innerHTML = result;
                };
            </script>
        </body>
        </html>
    `);
});

app.listen(port, () => {
    console.log(`Vulnerable Node.js app listening at http://localhost:${port}`);
}); 