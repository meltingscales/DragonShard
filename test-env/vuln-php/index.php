<?php
// Vulnerable PHP Application for Testing Genetic Fuzzer
// Contains multiple vulnerability types: SQL Injection, XSS, LFI, Command Injection, Path Traversal

session_start();

// Database connection (vulnerable)
$db_host = $_ENV['DB_HOST'] ?? 'mysql';
$db_user = $_ENV['DB_USER'] ?? 'testuser';
$db_pass = $_ENV['DB_PASS'] ?? 'testpass';
$db_name = $_ENV['DB_NAME'] ?? 'testdb';

try {
    $pdo = new PDO("mysql:host=$db_host;dbname=$db_name", $db_user, $db_pass);
    $pdo->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
} catch(PDOException $e) {
    // Don't show real error in production
    echo "Database connection failed";
}

// Handle form submissions
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $action = $_POST['action'] ?? '';
    
    switch($action) {
        case 'search':
            // VULNERABILITY 1: SQL Injection
            $search = $_POST['search'] ?? '';
            if ($search) {
                $query = "SELECT * FROM users WHERE name LIKE '%$search%'"; // VULNERABLE!
                try {
                    $stmt = $pdo->query($query);
                    $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                } catch(PDOException $e) {
                    $error = "SQL Error: " . $e->getMessage(); // VULNERABLE: Error disclosure
                }
            }
            break;
            
        case 'login':
            // VULNERABILITY 2: SQL Injection in login
            $username = $_POST['username'] ?? '';
            $password = $_POST['password'] ?? '';
            
            if ($username && $password) {
                $query = "SELECT * FROM users WHERE username='$username' AND password='$password'"; // VULNERABLE!
                try {
                    $stmt = $pdo->query($query);
                    $user = $stmt->fetch(PDO::FETCH_ASSOC);
                    if ($user) {
                        $_SESSION['user'] = $user;
                        $message = "Welcome " . $user['name']; // VULNERABILITY 3: XSS
                    }
                } catch(PDOException $e) {
                    $error = "Login failed: " . $e->getMessage(); // VULNERABLE: Error disclosure
                }
            }
            break;
            
        case 'file':
            // VULNERABILITY 4: Local File Inclusion
            $file = $_POST['file'] ?? '';
            if ($file) {
                $filepath = "files/" . $file; // VULNERABLE: No path validation
                if (file_exists($filepath)) {
                    $content = file_get_contents($filepath);
                    $file_content = htmlspecialchars($content);
                } else {
                    $error = "File not found: $filepath";
                }
            }
            break;
            
        case 'command':
            // VULNERABILITY 5: Command Injection
            $cmd = $_POST['command'] ?? '';
            if ($cmd) {
                $output = shell_exec("ping -c 1 $cmd"); // VULNERABLE!
                $command_output = htmlspecialchars($output);
            }
            break;
            
        case 'path':
            // VULNERABILITY 6: Path Traversal
            $path = $_POST['path'] ?? '';
            if ($path) {
                $full_path = "/var/www/html/" . $path; // VULNERABLE: No path validation
                if (file_exists($full_path)) {
                    $path_content = file_get_contents($full_path);
                    $path_output = htmlspecialchars($path_content);
                } else {
                    $error = "Path not found: $full_path";
                }
            }
            break;
            
        case 'complex':
            // VULNERABILITY 8: Complex Multi-Vector Attack
            $payload = $_POST['payload'] ?? '';
            $type = $_POST['type'] ?? '';
            
            if ($payload && $type) {
                switch($type) {
                    case 'sql_advanced':
                        // Advanced SQL Injection with UNION
                        $query = "SELECT * FROM users WHERE id = $payload"; // VULNERABLE!
                        try {
                            $stmt = $pdo->query($query);
                            $results = $stmt->fetchAll(PDO::FETCH_ASSOC);
                            $complex_output = "SQL Results: " . json_encode($results);
                        } catch(PDOException $e) {
                            $complex_output = "SQL Error: " . $e->getMessage(); // VULNERABLE
                        }
                        break;
                        
                    case 'xss_advanced':
                        // Advanced XSS with event handlers
                        $complex_output = "Found: $payload"; // VULNERABLE: XSS reflection
                        break;
                        
                    case 'command_advanced':
                        // Advanced Command Injection with multiple commands
                        $output = shell_exec("echo '$payload' | xargs -I {} sh -c '{}'"); // VULNERABLE!
                        $complex_output = "Command Output: " . htmlspecialchars($output);
                        break;
                        
                    case 'lfi_advanced':
                        // Advanced LFI with protocol wrappers
                        $content = file_get_contents($payload); // VULNERABLE: No validation
                        $complex_output = "File Content: " . htmlspecialchars($content);
                        break;
                        
                    case 'xxe_advanced':
                        // Advanced XXE with external entity
                        if (strpos($payload, '<?xml') !== false) {
                            $xml = simplexml_load_string($payload); // VULNERABLE: XXE
                            $complex_output = "XML Parsed: " . print_r($xml, true);
                        } else {
                            $complex_output = "Invalid XML payload";
                        }
                        break;
                        
                    case 'ssrf_advanced':
                        // Advanced SSRF with internal services
                        $url = $payload;
                        $response = file_get_contents($url); // VULNERABLE: SSRF
                        $complex_output = "SSRF Response: " . htmlspecialchars($response);
                        break;
                        
                    default:
                        $complex_output = "Unknown attack type: $type";
                }
            }
            break;
    }
}

// VULNERABILITY 7: Reflected XSS
$user_input = $_GET['input'] ?? '';
if ($user_input) {
    $reflected_output = $user_input; // VULNERABLE: No sanitization
}
?>

<!DOCTYPE html>
<html>
<head>
    <title>Vulnerable Test App</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        .section { margin: 20px 0; padding: 15px; border: 1px solid #ccc; }
        .vulnerable { background-color: #ffe6e6; }
        input, textarea { width: 100%; padding: 5px; margin: 5px 0; }
        button { padding: 10px; margin: 5px; }
        .error { color: red; }
        .success { color: green; }
    </style>
</head>
<body>
    <h1>Vulnerable Test Application</h1>
    <p>This application contains multiple vulnerabilities for testing the genetic fuzzer.</p>
    
    <?php if (isset($error)): ?>
        <div class="error"><?php echo $error; ?></div>
    <?php endif; ?>
    
    <?php if (isset($message)): ?>
        <div class="success"><?php echo $message; ?></div>
    <?php endif; ?>
    
    <!-- VULNERABILITY 1: SQL Injection -->
    <div class="section vulnerable">
        <h2>SQL Injection Test</h2>
        <form method="POST">
            <input type="hidden" name="action" value="search">
            <input type="text" name="search" placeholder="Search users..." value="<?php echo htmlspecialchars($_POST['search'] ?? ''); ?>">
            <button type="submit">Search</button>
        </form>
        <?php if (isset($results)): ?>
            <h3>Results:</h3>
            <pre><?php print_r($results); ?></pre>
        <?php endif; ?>
    </div>
    
    <!-- VULNERABILITY 2: SQL Injection Login -->
    <div class="section vulnerable">
        <h2>Vulnerable Login</h2>
        <form method="POST">
            <input type="hidden" name="action" value="login">
            <input type="text" name="username" placeholder="Username">
            <input type="password" name="password" placeholder="Password">
            <button type="submit">Login</button>
        </form>
    </div>
    
    <!-- VULNERABILITY 3: XSS -->
    <div class="section vulnerable">
        <h2>XSS Test</h2>
        <form method="POST">
            <input type="hidden" name="action" value="xss">
            <input type="text" name="xss_input" placeholder="Enter XSS payload">
            <button type="submit">Submit</button>
        </form>
        <?php if (isset($reflected_output)): ?>
            <div>Output: <?php echo $reflected_output; ?></div>
        <?php endif; ?>
    </div>
    
    <!-- VULNERABILITY 4: Local File Inclusion -->
    <div class="section vulnerable">
        <h2>File Inclusion Test</h2>
        <form method="POST">
            <input type="hidden" name="action" value="file">
            <input type="text" name="file" placeholder="File to include">
            <button type="submit">Include File</button>
        </form>
        <?php if (isset($file_content)): ?>
            <h3>File Content:</h3>
            <pre><?php echo $file_content; ?></pre>
        <?php endif; ?>
    </div>
    
    <!-- VULNERABILITY 5: Command Injection -->
    <div class="section vulnerable">
        <h2>Command Injection Test</h2>
        <form method="POST">
            <input type="hidden" name="action" value="command">
            <input type="text" name="command" placeholder="Command to execute">
            <button type="submit">Execute</button>
        </form>
        <?php if (isset($command_output)): ?>
            <h3>Command Output:</h3>
            <pre><?php echo $command_output; ?></pre>
        <?php endif; ?>
    </div>
    
    <!-- VULNERABILITY 6: Path Traversal -->
    <div class="section vulnerable">
        <h2>Path Traversal Test</h2>
        <form method="POST">
            <input type="hidden" name="action" value="path">
            <input type="text" name="path" placeholder="Path to traverse">
            <button type="submit">Read File</button>
        </form>
        <?php if (isset($path_output)): ?>
            <h3>File Content:</h3>
            <pre><?php echo $path_output; ?></pre>
        <?php endif; ?>
    </div>
    
    <!-- VULNERABILITY 7: Reflected XSS -->
    <div class="section vulnerable">
        <h2>Reflected XSS Test</h2>
        <p>Add ?input=payload to URL to test reflected XSS</p>
        <?php if (isset($reflected_output)): ?>
            <div>Reflected: <?php echo $reflected_output; ?></div>
        <?php endif; ?>
    </div>
    
    <div class="section">
        <h2>Test Files</h2>
        <p>Available test files:</p>
        <ul>
            <li><a href="?input=test">Test XSS</a></li>
            <li><a href="?input=<script>alert('XSS')</script>">XSS Payload</a></li>
            <li><a href="?input=1' OR '1'='1">SQL Injection</a></li>
        </ul>
    </div>
</body>
</html> 