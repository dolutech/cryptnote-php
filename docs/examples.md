# Code Examples

Comprehensive code examples for the CryptNote PHP Library.

## Table of Contents

- [Basic Usage](#basic-usage)
- [Password Protection](#password-protection)
- [Time Expiration](#time-expiration)
- [Multiple Views](#multiple-views)
- [Markdown and HTML Content](#markdown-and-html-content)
- [Standalone Encryption](#standalone-encryption)
- [Building a Web Interface](#building-a-web-interface)
- [Custom Storage Implementation](#custom-storage-implementation)
- [Error Handling](#error-handling)
- [Advanced Patterns](#advanced-patterns)

---

## Basic Usage

### Creating a Simple Note

```php
<?php
use CryptNote\CryptNote;

// Initialize with default settings
$cryptnote = new CryptNote();

// Create an encrypted note (self-destructs after 1 view)
$result = $cryptnote->create('This is my secret message!');

echo "Token: " . $result['token'] . "\n";
echo "Created at: " . $result['created_at'] . "\n";
```

### Viewing a Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

try {
    $note = $cryptnote->view($token);
    
    echo "Content: " . $note['content'] . "\n";
    echo "Remaining views: " . $note['remaining_views'] . "\n";
    
    if ($note['destroyed']) {
        echo "⚠️ This note has been permanently destroyed.\n";
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

### Checking Note Status

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$status = $cryptnote->status($token);

switch ($status['status']) {
    case 'active':
        echo "✅ Note is active\n";
        echo "Remaining views: {$status['remaining_views']}/{$status['max_views']}\n";
        echo "Requires password: " . ($status['requires_password'] ? 'Yes' : 'No') . "\n";
        if ($status['expires_at']) {
            echo "Expires at: {$status['expires_at']} UTC\n";
        }
        break;
        
    case 'expired':
        echo "❌ Note has expired\n";
        break;
        
    case 'not_found':
        echo "❌ Note not found or destroyed\n";
        break;
        
    case 'invalid_token':
        echo "❌ Invalid token format\n";
        break;
}
```

### Deleting a Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

if ($cryptnote->delete($token)) {
    echo "✅ Note deleted successfully\n";
} else {
    echo "❌ Note not found or already deleted\n";
}
```

---

## Password Protection

### Creating a Password-Protected Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$result = $cryptnote->create('This is a password-protected secret', [
    'password' => 'mySecretPassword123',
    'max_views' => 3,
]);

echo "Token: " . $result['token'] . "\n";
echo "Has password: " . ($result['has_password'] ? 'Yes' : 'No') . "\n";
```

### Viewing a Password-Protected Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// First, check if password is required
$status = $cryptnote->status($token);

if ($status['requires_password']) {
    // Prompt user for password
    $password = readline("Enter password: ");
    
    try {
        $note = $cryptnote->view($token, $password);
        echo "Content: " . $note['content'] . "\n";
    } catch (Exception $e) {
        if ($e->getMessage() === 'Incorrect password') {
            echo "❌ Wrong password. Please try again.\n";
        } else {
            echo "Error: " . $e->getMessage() . "\n";
        }
    }
} else {
    $note = $cryptnote->view($token);
    echo "Content: " . $note['content'] . "\n";
}
```

### Generating Strong Passwords

```php
<?php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

// Generate passwords with different options
$password1 = $crypto->generatePassword(16, true);   // With special chars
$password2 = $crypto->generatePassword(20, false);  // Alphanumeric only
$password3 = $crypto->generatePassword(24, true);   // Extra long

echo "Strong password: $password1\n";
echo "Alphanumeric: $password2\n";
echo "Extra secure: $password3\n";
```

---

## Time Expiration

### Creating a Time-Limited Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// Expires in 1 hour
$result = $cryptnote->create('Time-sensitive information', [
    'expire_minutes' => 60,
    'max_views' => 10,
]);

echo "Expires at: " . $result['expires_at'] . " UTC\n";

// Expires in 24 hours
$result = $cryptnote->create('Daily report', [
    'expire_minutes' => 1440,  // 24 * 60
]);

// Expires in 7 days (maximum)
$result = $cryptnote->create('Weekly summary', [
    'expire_minutes' => 10080,  // 7 * 24 * 60
]);
```

### Checking Expiration Status

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$status = $cryptnote->status($token);

if ($status['status'] === 'active' && $status['expires_at']) {
    $expiresAt = new DateTime($status['expires_at'], new DateTimeZone('UTC'));
    $now = new DateTime('now', new DateTimeZone('UTC'));
    $diff = $now->diff($expiresAt);
    
    if ($diff->days > 0) {
        echo "Expires in {$diff->days} days\n";
    } elseif ($diff->h > 0) {
        echo "Expires in {$diff->h} hours\n";
    } else {
        echo "Expires in {$diff->i} minutes\n";
    }
}
```

---

## Multiple Views

### Creating a Note with Multiple Views

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// Allow 5 views
$result = $cryptnote->create('Shared team secret', [
    'max_views' => 5,
]);

echo "This note can be viewed {$result['max_views']} times\n";
```

### Tracking View Count

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// Create note with 3 views
$result = $cryptnote->create('Limited access content', ['max_views' => 3]);
$token = $result['token'];

// Simulate multiple views
for ($i = 1; $i <= 3; $i++) {
    $note = $cryptnote->view($token);
    
    echo "View $i:\n";
    echo "  Content: {$note['content']}\n";
    echo "  Remaining: {$note['remaining_views']}\n";
    echo "  Destroyed: " . ($note['destroyed'] ? 'Yes' : 'No') . "\n\n";
}

// Fourth view will fail
try {
    $cryptnote->view($token);
} catch (Exception $e) {
    echo "Expected error: " . $e->getMessage() . "\n";
}
```

---

## Markdown and HTML Content

### Creating a Markdown Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$markdownContent = <<<MD
# Secret Document

This is a **confidential** document with:

- Item 1
- Item 2
- Item 3

## Code Example

```php
echo "Hello, World!";
```

> Important: This information is classified.
MD;

$result = $cryptnote->create($markdownContent, [
    'is_markdown' => true,
    'max_views' => 5,
]);

// When viewing, check is_markdown flag
$note = $cryptnote->view($result['token']);

if ($note['is_markdown']) {
    // Render as Markdown
    echo renderMarkdown($note['content']);
} else {
    echo htmlspecialchars($note['content']);
}
```

### Creating an HTML Note

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$htmlContent = <<<HTML
<div class="secret-document">
    <h1>Confidential Report</h1>
    <p>This is <strong>important</strong> information.</p>
    <ul>
        <li>Point 1</li>
        <li>Point 2</li>
    </ul>
</div>
HTML;

$result = $cryptnote->create($htmlContent, [
    'is_html' => true,
    'max_views' => 3,
]);

// When viewing
$note = $cryptnote->view($result['token']);

if ($note['is_html']) {
    // Sanitize HTML before displaying
    echo $htmlPurifier->purify($note['content']);
} else {
    echo htmlspecialchars($note['content']);
}
```

---

## Standalone Encryption

### Basic Encryption/Decryption

```php
<?php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

// Generate a key
$key = $crypto->generateKey();
echo "Key: $key\n";

// Encrypt
$message = "Hello, this is a secret message!";
$encrypted = $crypto->encrypt($message, $key);
echo "Encrypted: $encrypted\n";

// Decrypt
$decrypted = $crypto->decrypt($encrypted, $key);
echo "Decrypted: $decrypted\n";
```

### Password-Protected Encryption

```php
<?php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

$key = $crypto->generateKey();
$password = "userPassword123";
$message = "This requires a password to decrypt";

// Encrypt with password
$encrypted = $crypto->encryptWithPassword($message, $key, $password);

// Decrypt with password
$decrypted = $crypto->decryptWithPassword($encrypted, $key, $password);

echo "Original: $message\n";
echo "Decrypted: $decrypted\n";

// Wrong password will throw exception
try {
    $crypto->decryptWithPassword($encrypted, $key, "wrongPassword");
} catch (Exception $e) {
    echo "Error: " . $e->getMessage() . "\n";
}
```

### Token Generation and Validation

```php
<?php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

// Generate tokens
$token = $crypto->generateToken();        // 64 hex chars (default)
$shortToken = $crypto->generateToken(16); // 32 hex chars

echo "Standard token: $token\n";
echo "Short token: $shortToken\n";

// Validate tokens
$isValid = $crypto->validateToken($token);           // true
$isValid = $crypto->validateToken($shortToken, 32);  // true
$isValid = $crypto->validateToken("invalid");        // false
```

---

## Building a Web Interface

### Create Note Form (create.php)

```php
<?php
require_once 'vendor/autoload.php';

use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'db_path' => '/var/lib/cryptnote/notes.db',
    'base_url' => 'https://example.com/view.php',
]);

$message = '';
$shareUrl = '';
$error = '';

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
<html>
<head>
    <title>Create Secure Note</title>
</head>
<body>
    <h1>Create Secure Note</h1>
    
    <?php if ($message): ?>
        <div class="success">
            <?= htmlspecialchars($message) ?>
            <p>Share this link: <a href="<?= htmlspecialchars($shareUrl) ?>"><?= htmlspecialchars($shareUrl) ?></a></p>
        </div>
    <?php endif; ?>
    
    <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
    <?php endif; ?>
    
    <form method="POST">
        <div>
            <label>Content:</label>
            <textarea name="content" required></textarea>
        </div>
        
        <div>
            <label>Max Views:</label>
            <input type="number" name="max_views" value="1" min="1" max="20">
        </div>
        
        <div>
            <label>Expire (minutes):</label>
            <input type="number" name="expire_minutes" placeholder="Optional">
        </div>
        
        <div>
            <label>Password (optional):</label>
            <input type="password" name="password">
        </div>
        
        <div>
            <label>
                <input type="checkbox" name="is_markdown" value="1">
                Content is Markdown
            </label>
        </div>
        
        <button type="submit">Create Secure Link</button>
    </form>
</body>
</html>
```

### View Note Page (view.php)

```php
<?php
require_once 'vendor/autoload.php';

use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'db_path' => '/var/lib/cryptnote/notes.db',
]);

$token = $_GET['token'] ?? '';
$content = null;
$error = null;
$requiresPassword = false;
$status = null;

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
?>
<!DOCTYPE html>
<html>
<head>
    <title>View Secure Note</title>
</head>
<body>
    <h1>View Secure Note</h1>
    
    <?php if ($error): ?>
        <div class="error"><?= htmlspecialchars($error) ?></div>
        
    <?php elseif ($content !== null): ?>
        <?php if (!empty($status['destroyed'])): ?>
            <div class="warning">⚠️ This note has been destroyed.</div>
        <?php endif; ?>
        
        <div class="content">
            <?php if (!empty($status['is_markdown'])): ?>
                <?= renderMarkdown($content) ?>
            <?php else: ?>
                <?= nl2br(htmlspecialchars($content)) ?>
            <?php endif; ?>
        </div>
        
        <?php if (empty($status['destroyed'])): ?>
            <p>Remaining views: <?= $status['remaining_views'] ?></p>
        <?php endif; ?>
        
    <?php else: ?>
        <div class="warning">
            ⚠️ This note can only be viewed <?= $status['remaining_views'] ?> more time(s).
        </div>
        
        <form method="POST">
            <?php if ($requiresPassword): ?>
                <div>
                    <label>Password:</label>
                    <input type="password" name="password" required>
                </div>
            <?php endif; ?>
            
            <button type="submit" name="view" value="1">
                View Note (<?= $status['remaining_views'] ?> views remaining)
            </button>
        </form>
    <?php endif; ?>
</body>
</html>
```

---

## Custom Storage Implementation

### Using Redis for Storage

```php
<?php
use CryptNote\CryptNoteStandalone;

class RedisNoteStorage
{
    private CryptNoteStandalone $crypto;
    private Redis $redis;
    
    public function __construct(Redis $redis)
    {
        $this->crypto = new CryptNoteStandalone();
        $this->redis = $redis;
    }
    
    public function create(string $content, array $options = []): array
    {
        $token = $this->crypto->generateToken();
        $key = $this->crypto->generateKey();
        $password = $options['password'] ?? null;
        $maxViews = $options['max_views'] ?? 1;
        $expireSeconds = ($options['expire_minutes'] ?? 0) * 60;
        
        // Encrypt content
        if ($password) {
            $encrypted = $this->crypto->encryptWithPassword($content, $key, $password);
        } else {
            $encrypted = $this->crypto->encrypt($content, $key);
        }
        
        // Store in Redis
        $data = [
            'encrypted' => $encrypted,
            'key' => $key,
            'has_password' => $password !== null,
            'max_views' => $maxViews,
            'remaining_views' => $maxViews,
        ];
        
        $this->redis->hMSet("note:$token", $data);
        
        if ($expireSeconds > 0) {
            $this->redis->expire("note:$token", $expireSeconds);
        }
        
        return [
            'token' => $token,
            'has_password' => $password !== null,
            'max_views' => $maxViews,
        ];
    }
    
    public function view(string $token, ?string $password = null): array
    {
        $data = $this->redis->hGetAll("note:$token");
        
        if (empty($data)) {
            throw new Exception('Note not found');
        }
        
        // Decrypt
        if ($data['has_password']) {
            if (!$password) {
                throw new Exception('Password required');
            }
            $content = $this->crypto->decryptWithPassword($data['encrypted'], $data['key'], $password);
        } else {
            $content = $this->crypto->decrypt($data['encrypted'], $data['key']);
        }
        
        // Decrement views
        $remaining = $this->redis->hIncrBy("note:$token", 'remaining_views', -1);
        
        if ($remaining <= 0) {
            $this->redis->del("note:$token");
        }
        
        return [
            'content' => $content,
            'remaining_views' => max(0, $remaining),
            'destroyed' => $remaining <= 0,
        ];
    }
}

// Usage
$redis = new Redis();
$redis->connect('127.0.0.1', 6379);

$storage = new RedisNoteStorage($redis);

$result = $storage->create('Secret message', [
    'max_views' => 3,
    'expire_minutes' => 60,
]);

$note = $storage->view($result['token']);
```

### Using MySQL for Storage

```php
<?php
use CryptNote\CryptNoteStandalone;

class MySQLNoteStorage
{
    private CryptNoteStandalone $crypto;
    private PDO $db;
    
    public function __construct(PDO $db)
    {
        $this->crypto = new CryptNoteStandalone();
        $this->db = $db;
        $this->initTable();
    }
    
    private function initTable(): void
    {
        $this->db->exec("
            CREATE TABLE IF NOT EXISTS notes (
                token VARCHAR(64) PRIMARY KEY,
                encrypted_data TEXT NOT NULL,
                encryption_key VARCHAR(64) NOT NULL,
                has_password BOOLEAN DEFAULT FALSE,
                max_views INT NOT NULL DEFAULT 1,
                remaining_views INT NOT NULL DEFAULT 1,
                expires_at DATETIME NULL,
                created_at DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        ");
    }
    
    public function create(string $content, array $options = []): array
    {
        $token = $this->crypto->generateToken();
        $key = $this->crypto->generateKey();
        $password = $options['password'] ?? null;
        $maxViews = $options['max_views'] ?? 1;
        $expireMinutes = $options['expire_minutes'] ?? null;
        
        if ($password) {
            $encrypted = $this->crypto->encryptWithPassword($content, $key, $password);
        } else {
            $encrypted = $this->crypto->encrypt($content, $key);
        }
        
        $expiresAt = $expireMinutes 
            ? date('Y-m-d H:i:s', time() + $expireMinutes * 60)
            : null;
        
        $stmt = $this->db->prepare("
            INSERT INTO notes (token, encrypted_data, encryption_key, has_password, max_views, remaining_views, expires_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        ");
        
        $stmt->execute([
            $token, $encrypted, $key, $password !== null,
            $maxViews, $maxViews, $expiresAt
        ]);
        
        return ['token' => $token, 'has_password' => $password !== null];
    }
    
    public function view(string $token, ?string $password = null): array
    {
        $stmt = $this->db->prepare("
            SELECT * FROM notes 
            WHERE token = ? 
            AND remaining_views > 0
            AND (expires_at IS NULL OR expires_at > NOW())
        ");
        $stmt->execute([$token]);
        $data = $stmt->fetch(PDO::FETCH_ASSOC);
        
        if (!$data) {
            throw new Exception('Note not found or expired');
        }
        
        if ($data['has_password']) {
            if (!$password) throw new Exception('Password required');
            $content = $this->crypto->decryptWithPassword($data['encrypted_data'], $data['encryption_key'], $password);
        } else {
            $content = $this->crypto->decrypt($data['encrypted_data'], $data['encryption_key']);
        }
        
        // Decrement and possibly delete
        $remaining = $data['remaining_views'] - 1;
        
        if ($remaining <= 0) {
            $stmt = $this->db->prepare("DELETE FROM notes WHERE token = ?");
            $stmt->execute([$token]);
        } else {
            $stmt = $this->db->prepare("UPDATE notes SET remaining_views = ? WHERE token = ?");
            $stmt->execute([$remaining, $token]);
        }
        
        return [
            'content' => $content,
            'remaining_views' => max(0, $remaining),
            'destroyed' => $remaining <= 0,
        ];
    }
}
```

---

## Error Handling

### Comprehensive Error Handling

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

function viewNote(CryptNote $cryptnote, string $token, ?string $password = null): array
{
    try {
        return [
            'success' => true,
            'data' => $cryptnote->view($token, $password),
        ];
    } catch (Exception $e) {
        $errorCode = match($e->getMessage()) {
            'Invalid token format' => 'INVALID_TOKEN',
            'Note not found or expired' => 'NOT_FOUND',
            'Password required' => 'PASSWORD_REQUIRED',
            'Incorrect password' => 'WRONG_PASSWORD',
            default => 'UNKNOWN_ERROR',
        };
        
        return [
            'success' => false,
            'error' => $errorCode,
            'message' => $e->getMessage(),
        ];
    }
}

// Usage
$result = viewNote($cryptnote, $token, $password);

if ($result['success']) {
    echo "Content: " . $result['data']['content'];
} else {
    switch ($result['error']) {
        case 'PASSWORD_REQUIRED':
            // Show password form
            break;
        case 'WRONG_PASSWORD':
            // Show error, allow retry
            break;
        case 'NOT_FOUND':
            // Show "note destroyed" message
            break;
        default:
            // Show generic error
            break;
    }
}
```

---

## Advanced Patterns

### Rate Limiting

```php
<?php
class RateLimitedCryptNote
{
    private CryptNote $cryptnote;
    private Redis $redis;
    
    public function __construct(CryptNote $cryptnote, Redis $redis)
    {
        $this->cryptnote = $cryptnote;
        $this->redis = $redis;
    }
    
    public function view(string $token, ?string $password = null, string $ip = ''): array
    {
        $key = "rate_limit:{$ip}:{$token}";
        $attempts = $this->redis->incr($key);
        
        if ($attempts === 1) {
            $this->redis->expire($key, 60); // 1 minute window
        }
        
        if ($attempts > 5) {
            throw new Exception('Too many attempts. Please wait.');
        }
        
        return $this->cryptnote->view($token, $password);
    }
}
```

### Audit Logging

```php
<?php
class AuditedCryptNote
{
    private CryptNote $cryptnote;
    private Logger $logger;
    
    public function __construct(CryptNote $cryptnote, Logger $logger)
    {
        $this->cryptnote = $cryptnote;
        $this->logger = $logger;
    }
    
    public function create(string $content, array $options = []): array
    {
        $result = $this->cryptnote->create($content, $options);
        
        $this->logger->info('Note created', [
            'token_prefix' => substr($result['token'], 0, 8),
            'has_password' => $result['has_password'],
            'max_views' => $result['max_views'],
            'expires_at' => $result['expires_at'] ?? null,
        ]);
        
        return $result;
    }
    
    public function view(string $token, ?string $password = null): array
    {
        try {
            $result = $this->cryptnote->view($token, $password);
            
            $this->logger->info('Note viewed', [
                'token_prefix' => substr($token, 0, 8),
                'remaining_views' => $result['remaining_views'],
                'destroyed' => $result['destroyed'],
            ]);
            
            return $result;
        } catch (Exception $e) {
            $this->logger->warning('Note view failed', [
                'token_prefix' => substr($token, 0, 8),
                'error' => $e->getMessage(),
            ]);
            
            throw $e;
        }
    }
}
```

### Webhook Notifications

```php
<?php
class WebhookCryptNote
{
    private CryptNote $cryptnote;
    private string $webhookUrl;
    
    public function __construct(CryptNote $cryptnote, string $webhookUrl)
    {
        $this->cryptnote = $cryptnote;
        $this->webhookUrl = $webhookUrl;
    }
    
    public function view(string $token, ?string $password = null): array
    {
        $result = $this->cryptnote->view($token, $password);
        
        if ($result['destroyed']) {
            $this->sendWebhook([
                'event' => 'note_destroyed',
                'token_prefix' => substr($token, 0, 8),
                'timestamp' => date('c'),
            ]);
        }
        
        return $result;
    }
    
    private function sendWebhook(array $data): void
    {
        $ch = curl_init($this->webhookUrl);
        curl_setopt_array($ch, [
            CURLOPT_POST => true,
            CURLOPT_POSTFIELDS => json_encode($data),
            CURLOPT_HTTPHEADER => ['Content-Type: application/json'],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_TIMEOUT => 5,
        ]);
        curl_exec($ch);
        curl_close($ch);
    }
}
```

---

## See Also

- [API Reference](api-reference.md)
- [Configuration Guide](configuration.md)
- [Security Best Practices](security.md)
