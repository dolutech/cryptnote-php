<?php
/**
 * CryptNote PHP Library - View Note Page
 * 
 * Displays and decrypts a secure note.
 */

require_once __DIR__ . '/../../src/CryptNote.php';

use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'db_path' => __DIR__ . '/data/notes.db',
]);

$token = $_GET['token'] ?? '';
$content = null;
$error = null;
$requiresPassword = false;
$status = null;

// Check token
if (empty($token)) {
    $error = 'No token provided';
} else {
    $status = $cryptnote->status($token);
    
    if ($status['status'] === 'not_found') {
        $error = 'Note not found or has been destroyed';
    } elseif ($status['status'] === 'expired') {
        $error = 'This note has expired';
    } elseif ($status['status'] === 'invalid_token') {
        $error = 'Invalid token format';
    } else {
        $requiresPassword = $status['requires_password'];
        
        // Handle view request
        if ($_SERVER['REQUEST_METHOD'] === 'POST' && isset($_POST['view'])) {
            try {
                $password = $_POST['password'] ?? null;
                $note = $cryptnote->view($token, $password);
                $content = $note['content'];
                $status['remaining_views'] = $note['remaining_views'];
                $status['destroyed'] = $note['destroyed'];
                $status['is_markdown'] = $note['is_markdown'];
            } catch (Exception $e) {
                $error = $e->getMessage();
            }
        }
    }
}

// Simple Markdown to HTML converter
function renderMarkdown($text) {
    $text = htmlspecialchars($text);
    // Headers
    $text = preg_replace('/^### (.+)$/m', '<h3>$1</h3>', $text);
    $text = preg_replace('/^## (.+)$/m', '<h2>$1</h2>', $text);
    $text = preg_replace('/^# (.+)$/m', '<h1>$1</h1>', $text);
    // Bold and italic
    $text = preg_replace('/\*\*\*(.+?)\*\*\*/', '<strong><em>$1</em></strong>', $text);
    $text = preg_replace('/\*\*(.+?)\*\*/', '<strong>$1</strong>', $text);
    $text = preg_replace('/\*(.+?)\*/', '<em>$1</em>', $text);
    // Code
    $text = preg_replace('/`(.+?)`/', '<code>$1</code>', $text);
    // Line breaks
    $text = nl2br($text);
    return $text;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>CryptNote - View Secure Note</title>
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
        input[type="password"] {
            width: 100%;
            padding: 12px;
            border: 1px solid rgba(255,255,255,0.2);
            border-radius: 8px;
            background: rgba(0,0,0,0.3);
            color: #fff;
            font-size: 16px;
        }
        input:focus { outline: none; border-color: #4f46e5; }
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
        .error { background: rgba(239, 68, 68, 0.2); border: 1px solid #ef4444; }
        .warning { background: rgba(245, 158, 11, 0.2); border: 1px solid #f59e0b; }
        .success { background: rgba(34, 197, 94, 0.2); border: 1px solid #22c55e; }
        .content-box {
            background: rgba(0,0,0,0.3);
            padding: 20px;
            border-radius: 8px;
            white-space: pre-wrap;
            word-break: break-word;
            line-height: 1.6;
        }
        .content-box h1, .content-box h2, .content-box h3 { margin: 15px 0 10px; }
        .content-box code { background: rgba(255,255,255,0.1); padding: 2px 6px; border-radius: 4px; }
        .info { font-size: 14px; opacity: 0.8; margin-top: 15px; }
        .destroyed { color: #ef4444; font-weight: bold; }
        .footer {
            text-align: center;
            margin-top: 30px;
            opacity: 0.7;
            font-size: 14px;
        }
        .footer a { color: #60a5fa; text-decoration: none; }
        .back-link { display: block; text-align: center; margin-top: 20px; color: #60a5fa; text-decoration: none; }
    </style>
</head>
<body>
    <div class="container">
        <h1>🔓 View Secure Note</h1>
        
        <div class="card">
            <?php if ($error): ?>
                <div class="message error">
                    <strong>Error:</strong> <?= htmlspecialchars($error) ?>
                </div>
                <a href="index.php" class="back-link">← Create a new note</a>
                
            <?php elseif ($content !== null): ?>
                <?php if (!empty($status['destroyed'])): ?>
                    <div class="message warning">
                        <strong>⚠️ This note has been destroyed.</strong><br>
                        This was the last allowed view.
                    </div>
                <?php else: ?>
                    <div class="message success">
                        <strong>✓ Note decrypted successfully</strong>
                    </div>
                <?php endif; ?>
                
                <div class="form-group">
                    <label>Content:</label>
                    <div class="content-box">
                        <?php if (!empty($status['is_markdown'])): ?>
                            <?= renderMarkdown($content) ?>
                        <?php else: ?>
                            <?= htmlspecialchars($content) ?>
                        <?php endif; ?>
                    </div>
                </div>
                
                <div class="info">
                    <?php if (!empty($status['destroyed'])): ?>
                        <span class="destroyed">🔥 Note permanently destroyed</span>
                    <?php else: ?>
                        Remaining views: <?= $status['remaining_views'] ?>/<?= $status['max_views'] ?>
                    <?php endif; ?>
                </div>
                
                <a href="index.php" class="back-link">← Create a new note</a>
                
            <?php else: ?>
                <div class="message warning">
                    <strong>⚠️ Warning:</strong> This note can only be viewed <?= $status['remaining_views'] ?> more time(s).
                    After that, it will be permanently destroyed.
                </div>
                
                <form method="POST">
                    <?php if ($requiresPassword): ?>
                        <div class="form-group">
                            <label for="password">🔑 This note requires a password:</label>
                            <input type="password" name="password" id="password" placeholder="Enter password" required autofocus>
                        </div>
                    <?php endif; ?>
                    
                    <button type="submit" name="view" value="1">
                        👁️ View Note (<?= $status['remaining_views'] ?> view<?= $status['remaining_views'] > 1 ? 's' : '' ?> remaining)
                    </button>
                </form>
                
                <a href="index.php" class="back-link">← Cancel and go back</a>
            <?php endif; ?>
        </div>
        
        <div class="footer">
            Powered by <a href="https://github.com/dolutech/cryptnote-php">CryptNote PHP Library</a> by <a href="https://dolutech.com">Dolutech</a>
        </div>
    </div>
</body>
</html>
