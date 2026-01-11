# CryptNote PHP Library

A powerful, standalone PHP library for creating encrypted, self-destructing messages with view limits and optional password protection.

## Overview

CryptNote provides a secure way to share sensitive information that automatically destroys itself after being viewed. Built with security in mind, it uses AES-256-CBC encryption and PBKDF2 key derivation to protect your data.

```
┌─────────────────────────────────────────────────────────────┐
│                     CryptNote Architecture                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│   ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│   │  Create  │───▶│   Encrypt    │───▶│  Store in DB     │  │
│   │  Note    │    │  (AES-256)   │    │  (SQLite)        │  │
│   └──────────┘    └──────────────┘    └──────────────────┘  │
│                                                              │
│   ┌──────────┐    ┌──────────────┐    ┌──────────────────┐  │
│   │  View    │◀───│   Decrypt    │◀───│  Retrieve &      │  │
│   │  Note    │    │  (AES-256)   │    │  Decrement Views │  │
│   └──────────┘    └──────────────┘    └──────────────────┘  │
│                                                              │
│                         │                                    │
│                         ▼                                    │
│              ┌──────────────────────┐                       │
│              │  Auto-Destroy when   │                       │
│              │  views = 0 or expired│                       │
│              └──────────────────────┘                       │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

## Features

| Feature | Description |
|---------|-------------|
| 🔐 **AES-256-CBC Encryption** | Military-grade encryption for your messages |
| 🔑 **Password Protection** | Optional additional layer with PBKDF2 key derivation |
| 👁️ **View Limits** | Messages self-destruct after a specified number of views (1-100) |
| ⏰ **Time Expiration** | Set messages to expire after a certain time (up to 7 days) |
| 📝 **Markdown/HTML Support** | Store and retrieve formatted content |
| 🗄️ **SQLite Storage** | Zero-configuration database included |
| 🧹 **Auto Cleanup** | Automatic removal of old, unviewed messages |
| 🔒 **Secure Deletion** | Data is overwritten before deletion |

## Requirements

- PHP 8.0 or higher
- OpenSSL extension
- PDO extension with SQLite driver

## Quick Installation

### Via Composer (Recommended)

```bash
composer require dolutech/cryptnote-php
```

### Manual Installation

1. Download or clone the repository
2. Include the autoloader or require the files directly:

```php
require_once 'path/to/library-open/src/CryptNote.php';
require_once 'path/to/library-open/src/CryptNoteStandalone.php';
```

## Quick Start

### Create and View a Note

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

### Password-Protected Note

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

### Time-Expiring Note

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

## Two Classes, Two Use Cases

CryptNote provides two classes for different scenarios:

### CryptNote (Full Library)

Use when you want complete functionality with built-in SQLite storage:

```php
use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'db_path' => '/path/to/database.db',
]);

// Full CRUD operations with automatic storage
$result = $cryptnote->create('Secret message');
$note = $cryptnote->view($result['token']);
```

### CryptNoteStandalone (Encryption Only)

Use when you want to handle storage yourself (Redis, MySQL, custom solutions):

```php
use CryptNote\CryptNoteStandalone;

$crypto = new CryptNoteStandalone();

// Just encryption utilities - you handle storage
$key = $crypto->generateKey();
$encrypted = $crypto->encrypt('My secret data', $key);
$decrypted = $crypto->decrypt($encrypted, $key);
```

## Documentation

| Document | Description |
|----------|-------------|
| [API Reference](api-reference.md) | Complete API documentation for all methods |
| [Configuration](configuration.md) | All configuration options and best practices |
| [Security](security.md) | Security architecture and best practices |
| [Examples](examples.md) | Detailed code examples for common use cases |
| [Migration Guide](migration.md) | Version history and migration guides |
| [Contributing](contributing.md) | How to contribute to the project |

## License

MIT License - see [LICENSE](../LICENSE) file for details.

## Credits

Developed by [Dolutech](https://dolutech.com) - Based on [CryptNote.pro](https://cryptnote.pro) encryption system.

## Support

- **Issues**: [GitHub Issues](https://github.com/dolutech/cryptnote-php/issues)
- **Source**: [GitHub Repository](https://github.com/dolutech/cryptnote-php)
