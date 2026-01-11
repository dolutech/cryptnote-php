# API Reference

Complete API documentation for the CryptNote PHP Library.

## Table of Contents

- [CryptNote Class](#cryptnote-class)
  - [Constructor](#constructor)
  - [create()](#create)
  - [view()](#view)
  - [status()](#status)
  - [delete()](#delete)
  - [getStats()](#getstats)
- [CryptNoteStandalone Class](#cryptnotestandalone-class)
  - [Constructor](#standalone-constructor)
  - [generateToken()](#generatetoken)
  - [generateKey()](#generatekey)
  - [encrypt()](#encrypt)
  - [decrypt()](#decrypt)
  - [encryptWithPassword()](#encryptwithpassword)
  - [decryptWithPassword()](#decryptwithpassword)
  - [validateToken()](#validatetoken)
  - [secureCompare()](#securecompare)
  - [generatePassword()](#generatepassword)

---

## CryptNote Class

The main class providing full functionality with built-in SQLite storage.

```php
use CryptNote\CryptNote;
```

### Constructor

```php
public function __construct(array $config = [])
```

Initialize CryptNote with configuration options.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `array` | Configuration options (see [Configuration](configuration.md)) |

#### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `db_path` | `string` | `./data/cryptnote.db` | Path to SQLite database file |
| `encryption_method` | `string` | `AES-256-GCM` | OpenSSL cipher method (GCM default, AEAD) |
| `encryption_version` | `string` | `v2` | `v2` (AEAD) or legacy `v1` (CBC+HMAC) |
| `token_length` | `int` | `32` | Token length in bytes (produces 64 hex chars) |
| `max_content_length` | `int` | `50000` | Maximum content length in characters |
| `pbkdf2_iterations` | `int` | `100000` | PBKDF2 iterations for password derivation |
| `password_min_length` | `int` | `12` | Minimum password length enforced on create |
| `password_validator` | `callable|null` | `null` | Custom password validation callback |
| `require_password` | `bool` | `false` | Require passwords for all notes |
| `enable_key_wrapping` | `bool` | `false` | Wrap per-note keys with `wrapping_key` |
| `wrapping_key` | `string|null` | `null` | Application-provided wrapping key material |
| `privacy_mode` | `bool` | `false` | Hide status details for missing/expired/invalid tokens |
| `secure_delete` | `bool` | `false` | Use SQLite DELETE journal + secure_delete pragma |
| `auto_cleanup` | `bool` | `true` | Enable automatic cleanup of old records |
| `cleanup_days` | `int` | `15` | Days after which unviewed records are cleaned |
| `base_url` | `string` | `null` | Base URL for generating share links |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Invalid encryption method |
| `Exception` | Database connection failed |

#### Example

```php
$cryptnote = new CryptNote([
    'db_path' => '/var/data/notes.db',
    'base_url' => 'https://example.com/view',
    'pbkdf2_iterations' => 150000,
]);
```

---

### create()

```php
public function create(string $content, array $options = []): array
```

Create an encrypted note.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$content` | `string` | The content to encrypt |
| `$options` | `array` | Creation options |

#### Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `password` | `string\|null` | `null` | Optional password (min 12, max 100 chars) |
| `max_views` | `int` | `1` | Maximum views before destruction (1-100) |
| `expire_minutes` | `int\|null` | `null` | Minutes until expiration (1-10080, max 7 days) |
| `is_markdown` | `bool` | `false` | Whether content is Markdown |
| `is_html` | `bool` | `false` | Whether content is HTML (overrides `is_markdown`) |

#### Returns

```php
[
    'success' => true,
    'token' => 'abc123def456...',           // 64-character hex token
    'has_password' => false,
    'max_views' => 1,
    'is_markdown' => false,
    'is_html' => false,
    'expires_at' => '2026-01-15 12:00:00',  // UTC, null if no expiration
    'created_at' => '2026-01-15 11:00:00',  // UTC
    'share_url' => 'https://...',           // Only if base_url configured
]
```

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Content is empty |
| `Exception` | Content exceeds maximum length |
| `Exception` | Password less than 12 characters |
| `Exception` | Password exceeds 100 characters |
| `Exception` | Failed to generate unique token |

#### Example

```php
// Simple note
$result = $cryptnote->create('Secret message');

// Full options
$result = $cryptnote->create('# Secret Document', [
    'password' => 'strongPassword123',
    'max_views' => 5,
    'expire_minutes' => 1440,  // 24 hours
    'is_markdown' => true,
]);

echo "Share this link: " . $result['share_url'];
```

---

### view()

```php
public function view(string $token, ?string $password = null): array
```

View and decrypt a note. This decrements the view count and destroys the note when views reach zero.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$token` | `string` | The 64-character note token |
| `$password` | `string\|null` | Password if the note is protected |

#### Returns

```php
[
    'success' => true,
    'content' => 'The decrypted message',
    'is_markdown' => false,
    'is_html' => false,
    'remaining_views' => 0,
    'max_views' => 1,
    'expires_at' => null,
    'destroyed' => true,  // true if this was the last view
]
```

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Invalid token format |
| `Exception` | Note not found or expired |
| `Exception` | Password required (but not provided) |
| `Exception` | Incorrect password |

#### Example

```php
// View without password
try {
    $note = $cryptnote->view($token);
    echo $note['content'];
    
    if ($note['destroyed']) {
        echo "This note has been permanently destroyed.";
    } else {
        echo "Remaining views: " . $note['remaining_views'];
    }
} catch (Exception $e) {
    echo "Error: " . $e->getMessage();
}

// View with password
$note = $cryptnote->view($token, 'myPassword123');
```

---

### status()

```php
public function status(string $token): array
```

Check the status of a note without viewing it. Does not decrement view count.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$token` | `string` | The note token |

#### Returns

```php
[
    'success' => true,
    'status' => 'active',           // 'active', 'expired', 'not_found', 'invalid_token'
    'requires_password' => false,
    'is_markdown' => false,
    'is_html' => false,
    'max_views' => 3,
    'remaining_views' => 2,
    'expires_at' => null,
    'created_at' => '2026-01-15 11:00:00',
]
```

#### Status Values

| Status | Description |
|--------|-------------|
| `active` | Note exists and can be viewed |
| `expired` | Note has expired (time or views exhausted) |
| `not_found` | Note does not exist |
| `invalid_token` | Token format is invalid |

#### Example

```php
$status = $cryptnote->status($token);

switch ($status['status']) {
    case 'active':
        echo "Note is active with {$status['remaining_views']} views remaining";
        if ($status['requires_password']) {
            echo " (password required)";
        }
        break;
    case 'expired':
        echo "Note has expired";
        break;
    case 'not_found':
        echo "Note not found";
        break;
    case 'invalid_token':
        echo "Invalid token format";
        break;
}
```

---

### delete()

```php
public function delete(string $token): bool
```

Manually delete a note. Performs secure deletion by overwriting data before removal.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$token` | `string` | The note token |

#### Returns

| Type | Description |
|------|-------------|
| `bool` | `true` if deleted, `false` if not found or invalid token |

#### Example

```php
if ($cryptnote->delete($token)) {
    echo "Note deleted successfully";
} else {
    echo "Note not found or already deleted";
}
```

---

### getStats()

```php
public function getStats(): array
```

Get database statistics.

#### Returns

```php
[
    'total_notes' => 150,
    'unviewed_notes' => 45,
    'password_protected' => 30,
    'with_expiration' => 25,
]
```

#### Example

```php
$stats = $cryptnote->getStats();

echo "Total notes: " . $stats['total_notes'];
echo "Unviewed: " . $stats['unviewed_notes'];
echo "Password protected: " . $stats['password_protected'];
echo "With expiration: " . $stats['with_expiration'];
```

---

## CryptNoteStandalone Class

Standalone encryption utilities without database storage. Use this when you want to handle storage yourself.

```php
use CryptNote\CryptNoteStandalone;
```

<a name="standalone-constructor"></a>
### Constructor

```php
public function __construct(array $config = [])
```

Initialize standalone encryption utilities.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$config` | `array` | Configuration options |

#### Configuration Options

| Option | Type | Default | Description |
|--------|------|---------|-------------|
| `encryption_method` | `string` | `AES-256-GCM` | OpenSSL cipher method (GCM default, AEAD) |
| `encryption_version` | `string` | `v2` | `v2` (AEAD) or legacy `v1` (CBC+HMAC) |
| `pbkdf2_iterations` | `int` | `100000` | PBKDF2 iterations for password derivation |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Invalid encryption method |

#### Example

```php
$crypto = new CryptNoteStandalone([
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',
    'pbkdf2_iterations' => 150000,
]);
```

---

> **Note:** CryptNoteStandalone uses the same AEAD v2/v1 formats as `CryptNote` for compatibility. Prefer v2 (AES-256-GCM) unless you must interoperate with legacy v1 CBC+HMAC payloads.

### generateToken()


```php
public function generateToken(int $length = 32): string
```

Generate a secure random token.

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `$length` | `int` | `32` | Token length in bytes |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Hexadecimal token (length × 2 characters) |

#### Example

```php
$token = $crypto->generateToken();      // 64 hex characters
$token = $crypto->generateToken(16);    // 32 hex characters
```

---

### generateKey()

```php
public function generateKey(): string
```

Generate a random 256-bit encryption key.

#### Returns

| Type | Description |
|------|-------------|
| `string` | Base64-encoded 256-bit key |

#### Example

```php
$key = $crypto->generateKey();
// Example: "K7gNU3sdo+OL0wNhqoVWhr3g6s1xYv72ol/pe/Unols="
```

---

### encrypt()

```php
public function encrypt(string $content, string $key): string
```

Encrypt content using AES-256-GCM by default (legacy AES-256-CBC when `encryption_version` = `v1`).

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$content` | `string` | Content to encrypt |
| `$key` | `string` | Base64-encoded encryption key |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Base64-encoded encrypted data (IV + ciphertext) |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Encryption failed |

#### Example

```php
$key = $crypto->generateKey();
$encrypted = $crypto->encrypt('Secret message', $key);
```

---

### decrypt()

```php
public function decrypt(string $encryptedData, string $key): string
```

Decrypt content using AES-256-GCM by default (legacy AES-256-CBC when `encryption_version` = `v1`).

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$encryptedData` | `string` | Base64-encoded encrypted data |
| `$key` | `string` | Base64-encoded encryption key |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Decrypted content |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Invalid encrypted data |
| `Exception` | Decryption failed |

#### Example

```php
$decrypted = $crypto->decrypt($encrypted, $key);
echo $decrypted; // "Secret message"
```

---

### encryptWithPassword()

```php
public function encryptWithPassword(string $content, string $key, string $password): string
```

Encrypt content with password protection using AES-256-GCM by default (legacy AES-256-CBC with HMAC when `encryption_version` = `v1`).

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$content` | `string` | Content to encrypt |
| `$key` | `string` | Base64-encoded encryption key |
| `$password` | `string` | User password |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Base64-encoded encrypted data (salt + IV + ciphertext) |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Encryption with password failed |

#### Example

```php
$key = $crypto->generateKey();
$encrypted = $crypto->encryptWithPassword('Secret', $key, 'userPassword123');
```

---

### decryptWithPassword()

```php
public function decryptWithPassword(string $encryptedData, string $key, string $password): string
```

Decrypt content with password using AES-256-GCM by default (legacy AES-256-CBC with HMAC when `encryption_version` = `v1`).

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$encryptedData` | `string` | Base64-encoded encrypted data |
| `$key` | `string` | Base64-encoded encryption key |
| `$password` | `string` | User password |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Decrypted content |

#### Exceptions

| Exception | Condition |
|-----------|-----------|
| `Exception` | Invalid encrypted data |
| `Exception` | Decryption failed - incorrect password or corrupted data |

#### Example

```php
$decrypted = $crypto->decryptWithPassword($encrypted, $key, 'userPassword123');
```

---

### validateToken()

```php
public function validateToken(string $token, int $expectedLength = 64): bool
```

Validate token format.

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `$token` | `string` | - | Token to validate |
| `$expectedLength` | `int` | `64` | Expected length in hex characters |

#### Returns

| Type | Description |
|------|-------------|
| `bool` | `true` if valid format |

#### Example

```php
$isValid = $crypto->validateToken($token);           // Expects 64 chars
$isValid = $crypto->validateToken($token, 32);       // Expects 32 chars
```

---

### secureCompare()

```php
public function secureCompare(string $known, string $user): bool
```

Securely compare two strings using timing-safe comparison.

#### Parameters

| Parameter | Type | Description |
|-----------|------|-------------|
| `$known` | `string` | Known/expected string |
| `$user` | `string` | User-provided string |

#### Returns

| Type | Description |
|------|-------------|
| `bool` | `true` if strings are equal |

#### Example

```php
if ($crypto->secureCompare($storedToken, $userToken)) {
    echo "Tokens match";
}
```

---

### generatePassword()

```php
public function generatePassword(int $length = 16, bool $includeSpecial = true): string
```

Generate a secure random password.

#### Parameters

| Parameter | Type | Default | Description |
|-----------|------|---------|-------------|
| `$length` | `int` | `16` | Password length |
| `$includeSpecial` | `bool` | `true` | Include special characters |

#### Returns

| Type | Description |
|------|-------------|
| `string` | Random password |

#### Character Sets

- **Without special**: `a-z`, `A-Z`, `0-9`
- **With special**: Above + `!@#$%^&*()_+-=[]{}|;:,.<>?`

#### Example

```php
$password = $crypto->generatePassword();           // 16 chars with special
$password = $crypto->generatePassword(24);         // 24 chars with special
$password = $crypto->generatePassword(12, false);  // 12 chars, alphanumeric only
```

---

## Error Handling

All methods that can fail throw `Exception` with descriptive messages:

```php
try {
    $note = $cryptnote->view($token, $password);
} catch (Exception $e) {
    switch ($e->getMessage()) {
        case 'Invalid token format':
            // Handle invalid token
            break;
        case 'Note not found or expired':
            // Handle missing/expired note
            break;
        case 'Password required':
            // Prompt for password
            break;
        case 'Incorrect password':
            // Handle wrong password
            break;
        default:
            // Handle other errors
            break;
    }
}
```

---

## See Also

- [Configuration Options](configuration.md)
- [Security Best Practices](security.md)
- [Code Examples](examples.md)
