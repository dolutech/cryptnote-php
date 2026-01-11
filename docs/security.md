# Security Guide

Comprehensive security documentation for the CryptNote PHP Library.

## Table of Contents

- [Security Architecture](#security-architecture)
- [Encryption Details](#encryption-details)
- [Password Protection](#password-protection)
- [Secure Deletion](#secure-deletion)
- [Best Practices](#best-practices)
- [Threat Model](#threat-model)
- [Known Limitations](#known-limitations)
- [Security Checklist](#security-checklist)

---

## Security Architecture

CryptNote uses a layered security approach to protect sensitive data:

```
┌─────────────────────────────────────────────────────────────────┐
│                    Security Architecture                         │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Layer 1: Encryption                   │    │
│  │                                                          │    │
│  │   Content ──▶ AES-256-GCM ──▶ Encrypted Data (AEAD)     │    │
│  │              (Random 12-byte IV/nonce, 16-byte auth tag) │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │              Layer 2: Password Protection                │    │
│  │                     (Optional)                           │    │
│  │                                                          │    │
│  │   Password ──▶ PBKDF2-SHA256 ──▶ Derived Key            │    │
│  │              (100,000+ iterations)                       │    │
│  │                                                          │    │
│  │   Base Key + Derived Key ──▶ Combined Key               │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                Layer 3: Access Control                   │    │
│  │                                                          │    │
│  │   • View limits (1-100 views)                           │    │
│  │   • Time expiration (up to 7 days)                      │    │
│  │   • Automatic destruction                                │    │
│  └─────────────────────────────────────────────────────────┘    │
│                           │                                      │
│                           ▼                                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                Layer 4: Secure Storage                   │    │
│  │                                                          │    │
│  │   • SQLite with WAL mode                                │    │
│  │   • Secure deletion (overwrite before delete)           │    │
│  │   • Automatic cleanup of old records                    │    │
│  └─────────────────────────────────────────────────────────┘    │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

---

## Encryption Details

### AES-256-GCM (Default)

CryptNote defaults to AES-256-GCM (AEAD) for authenticated encryption.

**Specifications:**
- **Algorithm**: AES (Rijndael)
- **Key Size**: 256 bits (32 bytes)
- **IV (nonce)**: 12 bytes per encryption
- **Auth Tag**: 16 bytes (GCM authentication tag)

**Data Format (v2, no password):**
```
┌──────────────────────────────────────────────────────────────┐
│  Base64 Encoded (v2)                                          │
├──────────────────────────────────────────────────────────────┤
│  IV (12 bytes) │ Auth Tag (16 bytes) │ Encrypted Content     │
└──────────────────────────────────────────────────────────────┘
```

### AES-256-CBC (Legacy)

Legacy AES-256-CBC with HMAC-SHA256 is available via `encryption_version` = `v1` for backward compatibility.

**Specifications:**
- **Algorithm**: AES (Rijndael)
- **Key Size**: 256 bits (32 bytes)
- **Block Size**: 128 bits (16 bytes)
- **Mode**: CBC (Cipher Block Chaining)
- **IV**: Random 16 bytes per encryption
- **HMAC**: SHA-256 for integrity verification (32 bytes)

**Data Format (v1, no password):**
```
┌──────────────────────────────────────────────────────────────┐
│  Base64 Encoded (v1)                                          │
├──────────────────────────────────────────────────────────────┤
│  IV (16 bytes) │ Encrypted Content │ HMAC-SHA256 (32 bytes)  │
└──────────────────────────────────────────────────────────────┘
```

### Key Generation

Encryption keys are generated using cryptographically secure random bytes:

```php
// 256-bit key generation
$key = base64_encode(random_bytes(32));
```

**Entropy Sources:**
- `random_bytes()` - PHP's CSPRNG
- Additional entropy from `microtime()`, `getmypid()`, `uniqid()`
- SHA-256 hash for final key derivation

### Token Generation

Tokens are generated with high entropy to prevent guessing:

```php
// Token generation process
$entropy = random_bytes(32) . 
           hash('sha256', microtime(true) . getmypid() . uniqid('', true), true) .
           random_bytes(32);

$token = bin2hex(substr(hash('sha256', $entropy, true), 0, 32));
// Result: 64-character hexadecimal string
```

**Token Properties:**
- 64 hexadecimal characters (256 bits of entropy)
- Collision probability: ~1 in 2^256
- Validated format: `/^[a-f0-9]{64}$/i`

---

## Password Protection

### PBKDF2 Key Derivation

When password protection is enabled, CryptNote uses PBKDF2 (Password-Based Key Derivation Function 2) to derive a key from the user's password.

**Specifications:**
- **Algorithm**: PBKDF2-HMAC-SHA256
- **Iterations**: 100,000 (default, configurable)
- **Salt**: Random 16 bytes per encryption
- **Output**: 256-bit derived key

**Data Format (with password):**
```
┌──────────────────────────────────────────────────────────────┐
│  Base64 Encoded                                               │
├──────────────────────────────────────────────────────────────┤
│  Salt (16 bytes) │ IV (16 bytes) │ Encrypted Content         │
└──────────────────────────────────────────────────────────────┘
```

### Key Combination

The final encryption key combines the base key with the password-derived key:

```php
// Key combination process
$passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
$combinedKey = hash('sha256', $baseKey . $passwordKey, true);
```

This provides:
1. **Defense in depth**: Even if the database is compromised, password-protected notes require the password
2. **Unique keys**: Each note has a unique combined key
3. **Brute-force resistance**: PBKDF2 iterations slow down attacks

### Password Requirements

| Requirement | Value |
|-------------|-------|
| Minimum length | 12 characters |
| Maximum length | 100 characters |
| Character set | Any UTF-8 characters |

**Recommendations:**
- Use at least 16 characters for high-security environments
- Mix uppercase, lowercase, numbers, and symbols
- Use the built-in password generator for strong passwords

```php
$crypto = new CryptNoteStandalone();
$strongPassword = $crypto->generatePassword(20, true);
```

---

## Secure Deletion

CryptNote implements secure deletion to prevent data recovery:

### Deletion Process

```
┌─────────────────────────────────────────────────────────────┐
│                    Secure Deletion Process                   │
├─────────────────────────────────────────────────────────────┤
│                                                              │
│  1. Overwrite encrypted_data with random bytes (1KB)        │
│                         │                                    │
│                         ▼                                    │
│  2. Overwrite encryption_key with random bytes (64 bytes)   │
│                         │                                    │
│                         ▼                                    │
│  3. DELETE record from database                              │
│                         │                                    │
│                         ▼                                    │
│  4. VACUUM database (during cleanup)                         │
│                                                              │
└─────────────────────────────────────────────────────────────┘
```

### Automatic Destruction

Notes are automatically destroyed when:
1. **View limit reached**: After the last allowed view
2. **Time expired**: After the expiration time passes
3. **Cleanup runs**: Unviewed notes older than `cleanup_days`

---

## Best Practices

### Server Configuration

1. **Use HTTPS**
   ```apache
   # Apache - Force HTTPS
   RewriteEngine On
   RewriteCond %{HTTPS} off
   RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]
   ```

2. **Secure Headers**
   ```php
   header('Strict-Transport-Security: max-age=31536000; includeSubDomains');
   header('X-Content-Type-Options: nosniff');
   header('X-Frame-Options: DENY');
   header('X-XSS-Protection: 1; mode=block');
   header('Content-Security-Policy: default-src \'self\'');
   ```

3. **Database Location**
   ```php
   // Store outside web root
   'db_path' => '/var/lib/cryptnote/notes.db'
   ```

4. **File Permissions**
   ```bash
   chmod 700 /var/lib/cryptnote
   chmod 600 /var/lib/cryptnote/notes.db
   chown www-data:www-data /var/lib/cryptnote -R
   ```

### Application Security

1. **Rate Limiting**
   ```php
   // Implement rate limiting for password attempts
   class RateLimiter {
       public function checkLimit(string $ip, string $token): bool {
           // Allow max 5 attempts per minute per token
           // Implementation depends on your caching solution
       }
   }
   ```

2. **Input Validation**
   ```php
   // Always validate tokens before use
   if (!$cryptnote->validateToken($token)) {
       throw new Exception('Invalid token');
   }
   ```

3. **Error Handling**
   ```php
   // Don't expose internal errors
   try {
       $note = $cryptnote->view($token, $password);
   } catch (Exception $e) {
       // Log detailed error internally
       error_log($e->getMessage());
       
       // Show generic message to user
       echo "Unable to retrieve note";
   }
   ```

4. **Logging**
   ```php
   // Log access attempts (without sensitive data)
   $logger->info('Note access attempt', [
       'token_prefix' => substr($token, 0, 8),
       'ip' => $_SERVER['REMOTE_ADDR'],
       'success' => $success,
   ]);
   ```

### Content Security

1. **HTML Content**
   ```php
   // Always escape output
   echo htmlspecialchars($note['content'], ENT_QUOTES, 'UTF-8');
   ```

2. **Markdown Rendering**
   ```php
   // Use a secure Markdown parser
   // Sanitize HTML output
   $html = $markdownParser->parse($note['content']);
   $safeHtml = $htmlPurifier->purify($html);
   ```

---

## Threat Model

### Protected Against

| Threat | Protection |
|--------|------------|
| **Database theft** | Content is encrypted; password-protected notes require password |
| **Token guessing** | 256-bit tokens with ~10^77 possibilities |
| **Brute-force passwords** | PBKDF2 with 100,000+ iterations |
| **Data recovery** | Secure deletion overwrites data before removal |
| **Replay attacks** | View limits and expiration |
| **Timing attacks** | Constant-time comparison for tokens |

### Not Protected Against

| Threat | Mitigation |
|--------|------------|
| **Server compromise** | Use disk encryption, secure hosting |
| **Memory dumps** | Use encrypted swap, secure memory |
| **Network interception** | Always use HTTPS |
| **Weak passwords** | Enforce password policies, educate users |
| **Social engineering** | User education |
| **Malware on client** | Out of scope for server-side library |

### Attack Scenarios

#### Scenario 1: Database Stolen
```
Attacker obtains: encrypted_data, encryption_key, token

Without password:
- Attacker can decrypt content using stored key
- Mitigation: Use password protection for sensitive content

With password:
- Attacker needs password to derive combined key
- PBKDF2 makes brute-force expensive
- Mitigation: Use strong passwords
```

#### Scenario 2: Token Guessing
```
Token space: 16^64 = 2^256 possibilities
Attempts needed (50% probability): 2^255

At 1 billion attempts/second:
Time needed: ~10^60 years

Conclusion: Computationally infeasible
```

#### Scenario 3: Password Brute-Force
```
With 100,000 PBKDF2 iterations:
- ~10 attempts/second on modern hardware
- 6-char password (lowercase): ~3 days
- 8-char password (mixed): ~centuries
- 12-char password: ~heat death of universe

Mitigation: Require strong passwords, implement rate limiting
```

---

## Known Limitations

### Cryptographic Limitations

1. **CBC Mode (v1)**: Legacy CBC mode with HMAC provides integrity but is less efficient than GCM
   - Mitigation: Use default GCM mode (v2) for new implementations

2. **Key in Database**: Encryption key stored alongside encrypted data
   - Mitigation: Use password protection or enable `key_wrapping` for sensitive content

3. **PBKDF2 vs Argon2**: PBKDF2 is used for password derivation
   - Mitigation: For maximum security, consider Argon2id in future versions

### Operational Limitations

1. **Single Server**: No built-in clustering or replication
   - Mitigation: Use external database replication if needed

2. **SQLite Concurrency**: Limited concurrent write performance
   - Mitigation: Use MySQL/PostgreSQL for high-traffic applications

3. **No Key Rotation**: Keys are not automatically rotated
   - Mitigation: Implement key rotation if required

### Recovery Limitations

1. **No Recovery**: Destroyed notes cannot be recovered
   - This is by design for security

2. **Lost Passwords**: Cannot recover password-protected notes without password
   - This is by design for security

---

## Security Checklist

### Deployment Checklist

- [ ] Database stored outside web root
- [ ] Database file permissions set to 600
- [ ] Directory permissions set to 700
- [ ] HTTPS enabled and enforced
- [ ] Security headers configured
- [ ] Error messages don't expose internals
- [ ] Logging configured (without sensitive data)
- [ ] Rate limiting implemented
- [ ] Backup strategy in place (encrypted)

### Configuration Checklist

- [ ] `pbkdf2_iterations` >= 100,000
- [ ] `auto_cleanup` enabled
- [ ] `cleanup_days` set appropriately
- [ ] `base_url` uses HTTPS
- [ ] `db_path` outside web root

### Code Review Checklist

- [ ] All user input validated
- [ ] Output properly escaped
- [ ] Exceptions handled securely
- [ ] No sensitive data in logs
- [ ] Tokens validated before use
- [ ] Password requirements enforced

---

## Reporting Security Issues

If you discover a security vulnerability, please report it responsibly:

1. **Do not** open a public issue
2. Email security concerns to: contato@dolutech.com
3. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

---

## See Also

- [Configuration Guide](configuration.md)
- [API Reference](api-reference.md)
- [Examples](examples.md)
