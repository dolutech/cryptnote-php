# CryptNote PHP Library

[![Latest Version on Packagist](https://img.shields.io/packagist/v/dolutech/cryptnote-php.svg)](https://packagist.org/packages/dolutech/cryptnote-php)
[![PHP Version](https://img.shields.io/packagist/php-v/dolutech/cryptnote-php.svg)](https://packagist.org/packages/dolutech/cryptnote-php)
[![License](https://img.shields.io/packagist/l/dolutech/cryptnote-php.svg)](https://packagist.org/packages/dolutech/cryptnote-php)

A standalone PHP library for creating encrypted, self-destructing messages with view limits and optional password protection. Based on the [CryptNote.pro](https://cryptnote.pro) encryption system.

## Features

- 🔐 **AES-256-CBC Encryption** - Military-grade encryption for your messages
- 🔑 **Optional Password Protection** - Add an extra layer of security with PBKDF2 key derivation
- 👁️ **View Limits** - Messages self-destruct after a specified number of views
- ⏰ **Time Expiration** - Set messages to expire after a certain time
- 📝 **Markdown/HTML Support** - Store and retrieve formatted content
- 🗄️ **SQLite Storage** - Zero-configuration database included
- 🧹 **Auto Cleanup** - Automatic removal of old, unviewed messages
- 🔒 **Secure Deletion** - Data is overwritten before deletion

## Requirements

- PHP 8.0 or higher
- OpenSSL extension
- PDO extension with SQLite driver

## Installation

### Via Composer

```bash
composer require dolutech/cryptnote-php
```

### Manual Installation

1. Download or clone this repository
2. Include the autoloader or require the files directly:

```php
require_once 'path/to/library-open/src/CryptNote.php';
require_once 'path/to/library-open/src/CryptNoteStandalone.php';
```

## Quick Start

### Basic Usage (with built-in storage)

```php
<?php
use CryptNote\CryptNote;

// Initialize with default settings
$cryptnote = new CryptNote();

// Create an encrypted note
$result = $cryptnote->create('This is a secret message!', [
    'max_views' => 1,  // Self-destruct after 1 view
]);

echo "Token: " . $result['token'];
// Token: a1b2c3d4e5f6...

// View the note (this will decrement the view count)
$note = $cryptnote->view($result['token']);
echo $note['content'];
// Output: This is a secret message!

// The note is now destroyed (max_views reached)
```

### With Password Protection

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// Create a password-protected note
$result = $cryptnote->create('Top secret information', [
    'password' => 'mySecretPassword123',
    'max_views' => 3,
]);

// View requires the password
$note = $cryptnote->view($result['token'], 'mySecretPassword123');
echo $note['content'];
```

### With Time Expiration

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

// Create a note that expires in 60 minutes
$result = $cryptnote->create('Time-sensitive information', [
    'max_views' => 10,
    'expire_minutes' => 60,  // Expires in 1 hour
]);

echo "Expires at: " . $result['expires_at'];
```

### Check Note Status

```php
<?php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();

$status = $cryptnote->status($token);

if ($status['status'] === 'active') {
    echo "Note is active";
    echo "Remaining views: " . $status['remaining_views'];
    echo "Requires password: " . ($status['requires_password'] ? 'Yes' : 'No');
} elseif ($status['status'] === 'expired') {
    echo "Note has expired";
} else {
    echo "Note not found";
}
```

## Standalone Encryption (No Database)

If you want to handle storage yourself, use the `CryptNoteStandalone` class:

```php
<?php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

// Generate a key
$key = $crypto->generateKey();

// Encrypt
$encrypted = $crypto->encrypt('My secret data', $key);

// Decrypt
$decrypted = $crypto->decrypt($encrypted, $key);

// With password
$encrypted = $crypto->encryptWithPassword('My secret', $key, 'password123');
$decrypted = $crypto->decryptWithPassword($encrypted, $key, 'password123');
```

## Configuration Options

### CryptNote (Full Library)

```php
$cryptnote = new CryptNote([
    // Database path (default: ./data/cryptnote.db)
    'db_path' => '/path/to/your/database.db',
    
    // Encryption method (default: AES-256-CBC)
    'encryption_method' => 'AES-256-CBC',
    
    // Token length in bytes (default: 32, produces 64 hex chars)
    'token_length' => 32,
    
    // Maximum content length (default: 50000)
    'max_content_length' => 50000,
    
    // PBKDF2 iterations for password derivation (default: 100000)
    'pbkdf2_iterations' => 100000,
    
    // Enable automatic cleanup (default: true)
    'auto_cleanup' => true,
    
    // Days after which unviewed notes are cleaned (default: 15)
    'cleanup_days' => 15,
    
    // Base URL for generating share links (optional)
    'base_url' => 'https://yoursite.com/view',
]);
```

### CryptNoteStandalone

```php
$crypto = new CryptNoteStandalone([
    'encryption_method' => 'AES-256-CBC',
    'pbkdf2_iterations' => 100000,
]);
```

## API Reference

### CryptNote Class

#### `create(string $content, array $options = []): array`

Create an encrypted note.

**Options:**
- `password` (string|null): Optional password for additional protection
- `max_views` (int): Maximum views before destruction (1-100, default: 1)
- `expire_minutes` (int|null): Minutes until expiration (max: 10080 = 7 days)
- `is_markdown` (bool): Whether content is Markdown (default: false)
- `is_html` (bool): Whether content is HTML (default: false)

**Returns:**
```php
[
    'success' => true,
    'token' => 'abc123...',
    'has_password' => false,
    'max_views' => 1,
    'is_markdown' => false,
    'is_html' => false,
    'expires_at' => '2026-01-15 12:00:00',
    'created_at' => '2026-01-15 11:00:00',
    'share_url' => 'https://yoursite.com/view?token=abc123...',  // if base_url configured
]
```

#### `view(string $token, ?string $password = null): array`

View and decrypt a note.

**Returns:**
```php
[
    'success' => true,
    'content' => 'The decrypted message',
    'is_markdown' => false,
    'is_html' => false,
    'remaining_views' => 0,
    'max_views' => 1,
    'expires_at' => null,
    'destroyed' => true,
]
```

#### `status(string $token): array`

Check note status without viewing.

**Returns:**
```php
[
    'success' => true,
    'status' => 'active',  // 'active', 'expired', 'not_found', 'invalid_token'
    'requires_password' => false,
    'is_markdown' => false,
    'is_html' => false,
    'max_views' => 3,
    'remaining_views' => 2,
    'expires_at' => null,
    'created_at' => '2026-01-15 11:00:00',
]
```

#### `delete(string $token): bool`

Manually delete a note.

#### `getStats(): array`

Get database statistics.

### CryptNoteStandalone Class

#### `generateToken(int $length = 32): string`
Generate a secure random token.

#### `generateKey(): string`
Generate a random encryption key.

#### `encrypt(string $content, string $key): string`
Encrypt content.

#### `decrypt(string $encryptedData, string $key): string`
Decrypt content.

#### `encryptWithPassword(string $content, string $key, string $password): string`
Encrypt with password protection.

#### `decryptWithPassword(string $encryptedData, string $key, string $password): string`
Decrypt with password.

#### `validateToken(string $token, int $expectedLength = 64): bool`
Validate token format.

#### `generatePassword(int $length = 16, bool $includeSpecial = true): string`
Generate a secure random password.

## Security Considerations

1. **Database Security**: Ensure your SQLite database file is not publicly accessible. Store it outside the web root.
2. **HTTPS**: Always use HTTPS when transmitting tokens or passwords
3. **Password Strength**: Minimum 6 characters required. Encourage users to use strong passwords
4. **Key Storage**: Never log or expose encryption keys
5. **Secure Deletion**: The library overwrites data before deletion, but consider disk-level encryption for additional security
6. **PBKDF2**: Uses 100,000 iterations by default. For high-security applications, consider increasing or using Argon2id
7. **Rate Limiting**: Implement rate limiting in your application to prevent brute-force attacks on password-protected notes

## Building a Web Interface

Here's a simple example of building a web interface:

```php
<?php
// create.php
use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'base_url' => 'https://yoursite.com/view.php',
]);

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    $result = $cryptnote->create($_POST['content'], [
        'password' => $_POST['password'] ?: null,
        'max_views' => (int)$_POST['max_views'],
        'expire_minutes' => $_POST['expire_minutes'] ?: null,
    ]);
    
    echo "Share this link: " . $result['share_url'];
}
```

```php
<?php
// view.php
use CryptNote\CryptNote;

$cryptnote = new CryptNote();
$token = $_GET['token'] ?? '';

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    try {
        $note = $cryptnote->view($token, $_POST['password'] ?? null);
        echo htmlspecialchars($note['content']);
    } catch (Exception $e) {
        echo "Error: " . $e->getMessage();
    }
}
```

## License

MIT License - see [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Links

- **Packagist**: [packagist.org/packages/dolutech/cryptnote-php](https://packagist.org/packages/dolutech/cryptnote-php)
- **GitHub**: [github.com/dolutech/cryptnote-php](https://github.com/dolutech/cryptnote-php)
- **CryptNote.pro**: [cryptnote.pro](https://cryptnote.pro)

## Credits

Developed by [Dolutech](https://dolutech.com) - Based on [CryptNote.pro](https://cryptnote.pro) encryption system.
