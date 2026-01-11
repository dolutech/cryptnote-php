# Migration Guide

Version history, breaking changes, and migration guides for the CryptNote PHP Library.

## Table of Contents

- [Version History](#version-history)
- [Upgrade Guides](#upgrade-guides)
- [Breaking Changes](#breaking-changes)
- [Database Migrations](#database-migrations)

---

## Version History

### Version 0.2.0 (Current)

**Release Date**: January 2026

**New Features**:
- AES-256-GCM (AEAD) as default encryption for both classes
- Encryption versioning (`v2` for GCM, `v1` for legacy CBC+HMAC)
- Password policy: `password_min_length` (default: 12), `password_validator`, `require_password`
- Key wrapping: `enable_key_wrapping` and `wrapping_key` options
- Privacy mode: `privacy_mode` to hide status details
- Secure deletion: `secure_delete` for SQLite secure_delete pragma

**Changes**:
- Default encryption changed from AES-256-CBC to AES-256-GCM
- `CryptNoteStandalone` now uses versioned format (`v2:` or `v1:` prefix)
- Minimum password length increased to 12 characters

### Version 0.1.0

**Release Date**: January 2026

**Features**:
- Initial public release
- `CryptNote` class with SQLite storage
- `CryptNoteStandalone` class for encryption-only usage
- AES-256-CBC encryption with PBKDF2 password protection
- View limits, time expiration, Markdown/HTML support
- Automatic cleanup and secure deletion

**Requirements**:
- PHP 8.0+
- OpenSSL extension
- PDO extension with SQLite driver

---

## Upgrade Guides

### Upgrading from 0.1.0 to 0.2.0

#### Step 1: Backup Your Database

```bash
cp /path/to/cryptnote.db /path/to/cryptnote.db.backup
```

#### Step 2: Update the Library

```bash
composer update dolutech/cryptnote-php
```

#### Step 3: Test Backward Compatibility

Before deploying to production, verify that existing encrypted data can be decrypted:

```php
<?php
// test-compatibility.php
use CryptNote\CryptNote;

$cryptnote = new CryptNote([
    'db_path' => '/path/to/cryptnote.db',
]);

// Test decryption of existing notes
$testTokens = ['token1', 'token2']; // Add your test tokens

foreach ($testTokens as $token) {
    $status = $cryptnote->status($token);
    echo "Token: $token - Status: {$status['status']}\n";
    
    if ($status['status'] === 'active') {
        try {
            // For password-protected notes, provide the password
            $note = $cryptnote->view($token);
            echo "  ✅ Decryption successful\n";
        } catch (Exception $e) {
            echo "  ❌ Decryption failed: {$e->getMessage()}\n";
        }
    }
}
```

#### Step 4: Identify Data Formats

Check which format your existing data uses:

```php
// Data format detection
// - No prefix: Legacy 0.1.0 format (CBC without HMAC)
// - "v1:" prefix: CBC + HMAC format
// - "v2:" prefix: GCM AEAD format

// The library auto-detects and handles all formats
```

#### Step 5: Review Configuration Changes

The default encryption method changed from `AES-256-CBC` to `AES-256-GCM`. Existing notes encrypted with CBC will still be readable (backward compatible).

```php
// New defaults in 0.2.0
$cryptnote = new CryptNote([
    'encryption_method' => 'AES-256-GCM',  // Changed from AES-256-CBC
    'encryption_version' => 'v2',           // New option
    'password_min_length' => 12,            // New option (was 8)
]);
```

#### Step 6: Update Password Validation

If your application allowed passwords shorter than 12 characters, you may need to update your UI:

```php
// Old behavior (0.1.0): minimum 8 characters
// New behavior (0.2.0): minimum 12 characters by default

// To keep old behavior:
$cryptnote = new CryptNote([
    'password_min_length' => 8,
]);
```

#### Step 7: Standalone Class Changes

`CryptNoteStandalone` now produces versioned encrypted data:

```php
// 0.1.0 output: base64 encoded data
// 0.2.0 output: "v2:" + base64 (GCM) or "v1:" + base64 (CBC)

$crypto = new CryptNoteStandalone();
$encrypted = $crypto->encrypt('data', $key);
// Result: "v2:SGVsbG8gV29ybGQ..."

// Decryption auto-detects format (backward compatible)
$decrypted = $crypto->decrypt($encrypted, $key);
```

---

## Rollback Procedure

If critical issues occur after upgrading to 0.2.0:

### Step 1: Stop Your Application

Prevent new notes from being created while rolling back.

### Step 2: Restore Database Backup

```bash
# Stop application first
cp /path/to/cryptnote.db.backup /path/to/cryptnote.db
```

### Step 3: Downgrade Library

```bash
composer require dolutech/cryptnote-php:0.1.0
```

### Step 4: Verify Data Integrity

```php
<?php
// verify-rollback.php
use CryptNote\CryptNote;

$cryptnote = new CryptNote(['db_path' => '/path/to/cryptnote.db']);
$stats = $cryptnote->getStats();

echo "Total notes: {$stats['total_notes']}\n";
echo "Unviewed: {$stats['unviewed_notes']}\n";

// Test a sample of notes
```

### Important Notes

- Notes created with 0.2.0 (v2: format) will NOT be readable after downgrade to 0.1.0
- Only roll back if you haven't created new notes with 0.2.0
- Always test in staging environment first

---

## Breaking Changes

### Version 0.2.0

#### Encrypted Data Format

New notes use versioned format with `v2:` or `v1:` prefix:

| Version | Format | Description |
|---------|--------|-------------|
| 0.1.0 | `base64(iv + ciphertext)` | No version prefix |
| 0.2.0 | `v2:base64(iv + tag + ciphertext)` | GCM with auth tag |
| 0.2.0 | `v1:base64(iv + ciphertext + hmac)` | CBC with HMAC |

**Backward Compatibility**: The library can decrypt all formats. Old data without prefix is still supported.

#### Default Values Changed

| Setting | 0.1.0 | 0.2.0 |
|---------|-------|-------|
| `encryption_method` | `AES-256-CBC` | `AES-256-GCM` |
| `password_min_length` | 8 | 12 |

#### New Configuration Options

```php
// New in 0.2.0
$cryptnote = new CryptNote([
    'encryption_version' => 'v2',      // 'v2' (GCM) or 'v1' (CBC+HMAC)
    'password_min_length' => 12,       // Minimum password length
    'password_validator' => null,      // Custom validator callable
    'require_password' => false,       // Force passwords on all notes
    'enable_key_wrapping' => false,    // Wrap per-note keys
    'wrapping_key' => null,            // Wrapping key material
    'privacy_mode' => false,           // Hide status for invalid tokens
    'secure_delete' => false,          // SQLite secure_delete pragma
]);
```

---

## Database Migrations

### Schema (Unchanged)

The database schema remains the same between 0.1.0 and 0.2.0:

```sql
CREATE TABLE encrypted_content (
    token VARCHAR(64) PRIMARY KEY,
    encrypted_data TEXT NOT NULL,
    encryption_key TEXT NOT NULL,
    has_password BOOLEAN DEFAULT FALSE,
    is_markdown BOOLEAN DEFAULT FALSE,
    is_html BOOLEAN DEFAULT FALSE,
    max_views INTEGER NOT NULL DEFAULT 1,
    remaining_views INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL
);
```

### Data Migration

No data migration is required. The library automatically handles:
- Old CBC data without version prefix
- New v1 CBC+HMAC data with `v1:` prefix
- New v2 GCM data with `v2:` prefix

---

## Compatibility Matrix

| PHP Version | Library 0.1.x | Library 0.2.x |
|-------------|---------------|---------------|
| 8.0 | ✅ Supported | ✅ Supported |
| 8.1 | ✅ Supported | ✅ Supported |
| 8.2 | ✅ Supported | ✅ Supported |
| 8.3 | ✅ Supported | ✅ Supported |
| 7.4 | ❌ Not supported | ❌ Not supported |

---

## Getting Help

If you encounter issues during migration:

1. **Check the documentation**: Review the [API Reference](api-reference.md)
2. **Search issues**: Look for similar issues on [GitHub](https://github.com/dolutech/cryptnote-php/issues)
3. **Open an issue**: Provide your PHP version, library version, and error messages

---

## See Also

- [API Reference](api-reference.md)
- [Configuration Guide](configuration.md)
- [Security Guide](security.md)
