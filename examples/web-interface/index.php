<?php
/**
 * CryptNote PHP Library - Simple Web Interface Example
 * 
 * A minimal web interface demonstrating how to build a CryptNote-like
 * application using the library.
 * 
 * To run: php -S localhost:8080 -t examples/web-interface
 */

require_once __DIR__ . '/../../src/CryptNote.php';

use CryptNote\CryptNote;

// Initialize CryptNote
// Note: In production, use a hardcoded base_url or validate against an allowlist
$allowedHosts = ['localhost:8080', 'localhost', '127.0.0.1:8080'];
$host = $_SERVER['HTTP_HOST'] ?? 'localhost:8080';
if (!in_array($host, $allowedHosts, true)) {
    $host = 'localhost:8080';
}

$cryptnote = new CryptNote([
    'db_path' => __DIR__ . '/data/notes.db',
    'base_url' => 'http://' . $host . '/view.php',
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',
    'password_min_length' => 12,
]);

$message = '';
$shareUrl = '';
$error = '';

// Handle form submission
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $content = trim($_POST['content'] ?? '');
        
        if (empty($content)) {
            throw new Exception('Content cannot be empty');
        }
        
        $options = [
            'max_views' => max(1, min(20, (int)($_POST['max_views'] ?? 1))),
        ];
        
        if (!empty($_POST['password'])) {
            $options['password'] = $_POST['password'];
        }

        // Enforce minimum length in UI feedback
        if (!empty($_POST['password']) && strlen($_POST['password']) < 12) {
            throw new Exception('Password must be at least 12 characters');
        }
        
        if (!empty($_POST['expire_minutes'])) {
            $options['expire_minutes'] = (int)$_POST['expire_minutes'];
        }
        
        if (!empty($_POST['is_markdown'])) {
            $options['is_markdown'] = true;
        }
        
        $result = $cryptnote->create($content, $options);
        $shareUrl = $result['share_url'];
        $message = 'Secure link created successfully!';
        
    } catch (Exception $e) {
        $error = $e->getMessage();
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptNote - Create Secure Note</title>
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body { 
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%);
            min-height: 100vh;
            padding: 40px 20px;
            color: #fff;
        }
        .container { max-width: 600px; margin: 0 auto; }
        h1 { text-align: center; margin-bottom: 30px; font-size: 2rem; }
        .card {
            background: rgba(255,255,255,0.1);
            border-radius: 16px;
            padding: 30px;
            backdrop-filter: blur(10px);
        }
        .form-group { margin-bottom: 20px; }
        label { display: block; margin-bottom: 8px; font-weight: 500; }
        textarea, input[type="text"], input[type="password"], input[type="number"], select {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 16px;
        }
        textarea { min-height: 150px; resize: vertical; }
        textarea:focus, input:focus, select:focus {
            outline: none;
            border-color: #4f46e5;
        }
        .checkbox-group { display: flex; align-items: center; gap: 10px; }
        .checkbox-group input { width: auto; }
        button {
            width: 100%;
            padding: 14px;
            background: linear-gradient(135deg, #4f46e5 0%, #7c3aed 100%);
            border: none;
            border-radius: 8px;
            color: #fff;
            font-size: 16px;
            font-weight: 600;
            cursor: pointer;
            transition: transform 0.2s, box-shadow 0.2s;
        }
        button:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(79, 70, 229, 0.3);
        }
        .message {
            padding: 15px;
            border-radius: 8px;
            margin-bottom: 20px;
        }
        .success { background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; }
        .error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; }
        .share-url {
            background: rgba(0,0,0,0.3);
            padding: 15px;
            border-radius: 8px;
            word-break: break-all;
            margin-top: 10px;
        }
        .share-url a { color: #60a5fa; text-decoration: none; }
        .share-url a:hover { text-decoration: underline; }
        .row { display: flex; gap: 15px; }
        .row .form-group { flex: 1; }
        .footer {
            text-align: center;
            margin-top: 30px;
            opacity: 0.7;
            font-size: 14px;
        }
        .footer a { color: #60a5fa; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔐 CryptNote</h1>
        
        <div class="card">
            <?php if ($message): ?>
                <div class="message success">
                    <strong><?= htmlspecialchars($message) ?></strong>
                    <div class="share-url">
                        <a href="<?= htmlspecialchars($shareUrl) ?>" target="_blank"><?= htmlspecialchars($shareUrl) ?></a>
                    </div>
                </div>
            <?php endif; ?>
            
            <?php if ($error): ?>
                <div class="message error">
                    <strong>Error:</strong> <?= htmlspecialchars($error) ?>
                </div>
            <?php endif; ?>
            
            <form method="POST">
                <div class="form-group">
                    <label for="content">Secret Content</label>
                    <textarea name="content" id="content" placeholder="Enter your secret message..." required></textarea>
                </div>
                
                <div class="row">
                    <div class="form-group">
                        <label for="max_views">Max Views</label>
                        <input type="number" name="max_views" id="max_views" value="1" min="1" max="20">
                    </div>
                    
                    <div class="form-group">
                        <label for="expire_minutes">Expire (minutes)</label>
                        <input type="number" name="expire_minutes" id="expire_minutes" placeholder="Optional" min="1" max="10080">
                    </div>
                </div>
                
                <div class="form-group">
                    <label for="password">Password (optional)</label>
                    <input type="password" name="password" id="password" placeholder="Leave empty for no password">
                </div>
                
                <div class="form-group">
                    <div class="checkbox-group">
                        <input type="checkbox" name="is_markdown" id="is_markdown" value="1">
                        <label for="is_markdown" style="margin: 0;">Content is Markdown</label>
                    </div>
                </div>
                
                <button type="submit">🔒 Create Secure Link</button>
            </form>
        </div>
        
        <div class="footer">
            Powered by <a href="https://github.com/dolutech/cryptnote-php">CryptNote PHP Library</a> by <a href="https://dolutech.com">Dolutech</a>
        </div>
    </div>
</body>
</html>
