# Configuration Guide

Complete guide to configuring the CryptNote PHP Library.

## Table of Contents

- [CryptNote Configuration](#cryptnote-configuration)
- [CryptNoteStandalone Configuration](#cryptnotestandalone-configuration)
- [Configuration Examples](#configuration-examples)
- [Best Practices](#best-practices)
- [Environment-Specific Settings](#environment-specific-settings)

---

## CryptNote Configuration

The main `CryptNote` class accepts a configuration array in its constructor.

### All Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `db_path` | `string` | `./data/cryptnote.db` | Path to SQLite database file |
| `encryption_method` | `string` | `AES-256-GCM` | OpenSSL cipher method (GCM recommended default) |
| `encryption_version` | `string` | `v2` | `v2` (AEAD) or legacy `v1` (CBC+HMAC) |
| `token_length` | `int` | `32` | Token length in bytes |
| `max_content_length` | `int` | `50000` | Maximum content length in characters |
| `pbkdf2_iterations` | `int` | `100000` | PBKDF2 iterations for password derivation |
| `password_min_length` | `int` | `12` | Minimum password length enforced on create |
| `password_validator` | `callable|null` | `null` | Custom password validation callback (return false to reject) |
| `require_password` | `bool` | `false` | Require passwords for all notes |
| `enable_key_wrapping` | `bool` | `false` | Wrap per-note keys with `wrapping_key` |
| `wrapping_key` | `string|null` | `null` | Application-provided wrapping key material |
| `privacy_mode` | `bool` | `false` | Hide status details for missing/expired/invalid tokens |
| `secure_delete` | `bool` | `false` | Use SQLite DELETE journal + secure_delete pragma |
| `auto_cleanup` | `bool` | `true` | Enable automatic cleanup of old records |
| `cleanup_days` | `int` | `15` | Days after which unviewed records are cleaned |
| `base_url` | `string` | `null` | Base URL for generating share links |

### Detailed Option Descriptions

#### db_path

Path to the SQLite database file. The directory will be created automatically if it doesn't exist.

```php
$cryptnote = new CryptNote([
    'db_path' => '/var/lib/cryptnote/notes.db',
]);
```

**Security Note**: Store the database outside the web root to prevent direct access.

```
✅ Good: /var/lib/cryptnote/notes.db
❌ Bad:  /var/www/html/data/notes.db
```

#### encryption_method

The OpenSSL cipher method to use. Must be a valid method from `openssl_get_cipher_methods()`.

```php
$cryptnote = new CryptNote([
    'encryption_method' => 'AES-256-GCM',  // Recommended default (AEAD)
    'encryption_version' => 'v2',          // AEAD format
]);
```

**Supported Methods** (recommended):
- `AES-256-GCM` (default, AEAD with integrity)
- `AES-256-CBC` (legacy-compatible when using `encryption_version` = `v1`)
- `AES-128-CBC`

#### token_length

Length of generated tokens in bytes. The resulting hex string will be twice this length.

```php
$cryptnote = new CryptNote([
    'token_length' => 32,  // Produces 64-character hex tokens
]);
```

| Bytes | Hex Length | Security Level |
|-------|------------|----------------|
| 16 | 32 chars | Minimum |
| 32 | 64 chars | Recommended |
| 64 | 128 chars | High security |

#### max_content_length

Maximum allowed content length in characters.

```php
$cryptnote = new CryptNote([
    'max_content_length' => 100000,  // 100KB
]);
```

**Considerations**:
- Larger values increase database size
- Consider your storage capacity
- Default (50,000) is suitable for most text content

#### pbkdf2_iterations

Number of PBKDF2 iterations for password-based key derivation. Higher values increase security but also processing time.

```php
$cryptnote = new CryptNote([
    'pbkdf2_iterations' => 100000,  // Default
]);
```

| Iterations | Security | Performance |
|------------|----------|-------------|
| 10,000 | Minimum | Fast |
| 100,000 | Good (default) | Balanced |
| 250,000 | High | Slower |
| 600,000 | Very High | Slow |

**Recommendation**: Use at least 100,000 iterations. For high-security applications, consider 250,000+. Keep in mind password validation policy (`password_min_length` and optional `password_validator`).

#### auto_cleanup

Enable automatic cleanup of old, unviewed records.

```php
$cryptnote = new CryptNote([
    'auto_cleanup' => true,  // Default
]);
```

When enabled:
- Runs once per day (tracked via marker file)
- Removes unviewed notes older than `cleanup_days`
- Removes expired notes
- Runs `VACUUM` to reclaim space

#### cleanup_days

Number of days after which unviewed notes are automatically deleted.

```php
$cryptnote = new CryptNote([
    'cleanup_days' => 15,  // Default
]);
```

**Note**: Only affects notes that have never been viewed. Partially viewed notes are not affected.

#### base_url

Base URL for generating shareable links. When set, `create()` returns a `share_url` field.

```php
$cryptnote = new CryptNote([
    'base_url' => 'https://example.com/view.php',
]);

$result = $cryptnote->create('Secret');
echo $result['share_url'];
// https://example.com/view.php?token=abc123...
```

---

## CryptNoteStandalone Configuration

The standalone class has fewer configuration options since it doesn't handle storage.

### All Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `encryption_method` | `string` | `AES-256-GCM` | OpenSSL cipher method (GCM default, AEAD)
| `encryption_version` | `string` | `v2` | `v2` (AEAD) or legacy `v1` (CBC+HMAC)
| `pbkdf2_iterations` | `int` | `100000` | PBKDF2 iterations for password derivation |

### Example

```php
$crypto = new CryptNoteStandalone([
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',
    'pbkdf2_iterations' => 150000,
]);
```

---

## Configuration Examples

### Development Configuration

```php
$cryptnote = new CryptNote([
    'db_path' => __DIR__ . '/data/dev_notes.db',
    'auto_cleanup' => false,  // Disable for debugging
    'cleanup_days' => 1,
    'pbkdf2_iterations' => 10000,  // Faster for development
    'base_url' => 'http://localhost:8080/view.php',
]);
```

### Production Configuration

```php
$cryptnote = new CryptNote([
    'db_path' => '/var/lib/cryptnote/production.db',
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',      // AEAD default
    'token_length' => 32,
    'max_content_length' => 50000,
    'password_min_length' => 12,
    'require_password' => false,        // set true to force passwords for all notes
    'pbkdf2_iterations' => 250000,      // Higher security
    'enable_key_wrapping' => false,     // set true and provide wrapping_key to wrap per-note keys
    'wrapping_key' => null,
    'privacy_mode' => true,             // hide status for missing/expired/invalid tokens
    'secure_delete' => true,            // enable SQLite secure_delete + delete journal
    'auto_cleanup' => true,
    'cleanup_days' => 7,
    'base_url' => 'https://secure.example.com/view',
]);
```

### High-Security Configuration

```php
$cryptnote = new CryptNote([
    'db_path' => '/secure/encrypted-volume/notes.db',
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',
    'token_length' => 64,               // Longer tokens
    'max_content_length' => 10000,      // Limit content size
    'password_min_length' => 16,
    'require_password' => true,
    'pbkdf2_iterations' => 600000,      // Maximum security
    'enable_key_wrapping' => true,
    'wrapping_key' => getenv('CRYPTNOTE_WRAPPING_KEY'),
    'privacy_mode' => true,
    'secure_delete' => true,
    'auto_cleanup' => true,
    'cleanup_days' => 1,                // Quick cleanup
    'base_url' => 'https://secure.example.com/view',
]);
```

### Using Environment Variables

```php
$cryptnote = new CryptNote([
    'db_path' => getenv('CRYPTNOTE_DB_PATH') ?: '/var/lib/cryptnote/notes.db',
    'pbkdf2_iterations' => (int)(getenv('CRYPTNOTE_PBKDF2_ITERATIONS') ?: 100000),
    'base_url' => getenv('CRYPTNOTE_BASE_URL'),
    'cleanup_days' => (int)(getenv('CRYPTNOTE_CLEANUP_DAYS') ?: 15),
]);
```

**.env file:**
```bash
CRYPTNOTE_DB_PATH=/var/lib/cryptnote/notes.db
CRYPTNOTE_PBKDF2_ITERATIONS=250000
CRYPTNOTE_BASE_URL=https://example.com/view
CRYPTNOTE_CLEANUP_DAYS=7
```

---

## Best Practices

### Database Location

```
Recommended directory structure:

/var/lib/cryptnote/
├── notes.db          # Main database
├── notes.db-wal      # Write-ahead log (auto-created)
├── notes.db-shm      # Shared memory (auto-created)
└── .cleanup.touch    # Cleanup marker (auto-created)
```

**Permissions:**
```bash
# Create directory with restricted permissions
mkdir -p /var/lib/cryptnote
chown www-data:www-data /var/lib/cryptnote
chmod 700 /var/lib/cryptnote
```

### Security Recommendations

1. **Store database outside web root**
   ```php
   // ✅ Good
   'db_path' => '/var/lib/cryptnote/notes.db'
   
   // ❌ Bad
   'db_path' => '/var/www/html/data/notes.db'
   ```

2. **Use strong PBKDF2 iterations**
   ```php
   // Production minimum
   'pbkdf2_iterations' => 100000
   
   // High security
   'pbkdf2_iterations' => 250000
   ```

3. **Enable auto-cleanup**
   ```php
   'auto_cleanup' => true,
   'cleanup_days' => 7,  // Adjust based on your needs
   ```

4. **Use HTTPS for base_url**
   ```php
   // ✅ Good
   'base_url' => 'https://secure.example.com/view'
   
   // ❌ Bad
   'base_url' => 'http://example.com/view'
   ```

### Performance Tuning

For high-traffic applications:

```php
$cryptnote = new CryptNote([
    // Reduce PBKDF2 iterations if performance is critical
    // (but not below 100,000 for production)
    'pbkdf2_iterations' => 100000,
    
    // Limit content size to reduce database I/O
    'max_content_length' => 25000,
    
    // More frequent cleanup to keep database small
    'cleanup_days' => 3,
]);
```

---

## Environment-Specific Settings

### Recommended Settings by Environment

| Setting | Development | Staging | Production |
|---------|-------------|---------|------------|
| `db_path` | `./data/dev.db` | `/var/lib/cryptnote/staging.db` | `/var/lib/cryptnote/prod.db` |
| `pbkdf2_iterations` | 10,000 | 100,000 | 250,000 |
| `auto_cleanup` | `false` | `true` | `true` |
| `cleanup_days` | 30 | 15 | 7 |
| `base_url` | `http://localhost:8080/view` | `https://staging.example.com/view` | `https://example.com/view` |

### Configuration Factory Pattern

```php
class CryptNoteFactory
{
    public static function create(string $environment = 'production'): CryptNote
    {
        $configs = [
            'development' => [
                'db_path' => __DIR__ . '/data/dev.db',
                'pbkdf2_iterations' => 10000,
                'auto_cleanup' => false,
                'base_url' => 'http://localhost:8080/view.php',
            ],
            'staging' => [
                'db_path' => '/var/lib/cryptnote/staging.db',
                'pbkdf2_iterations' => 100000,
                'auto_cleanup' => true,
                'cleanup_days' => 15,
                'base_url' => 'https://staging.example.com/view',
            ],
            'production' => [
                'db_path' => '/var/lib/cryptnote/production.db',
                'pbkdf2_iterations' => 250000,
                'auto_cleanup' => true,
                'cleanup_days' => 7,
                'base_url' => 'https://example.com/view',
            ],
        ];
        
        return new CryptNote($configs[$environment] ?? $configs['production']);
    }
}

// Usage
$cryptnote = CryptNoteFactory::create(getenv('APP_ENV') ?: 'production');
```

---

## See Also

- [API Reference](api-reference.md)
- [Security Best Practices](security.md)
- [Code Examples](examples.md)
