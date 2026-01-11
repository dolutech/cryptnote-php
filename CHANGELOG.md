# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.2.0] - 2026-01-11

### Added
- **AES-256-GCM (AEAD)** as default encryption method for both `CryptNote` and `CryptNoteStandalone`
- **Encryption versioning** (`encryption_version`): `v2` (GCM AEAD) and `v1` (legacy CBC+HMAC)
- **Password policy enforcement**: `password_min_length` (default: 12 characters)
- **Custom password validator**: `password_validator` callable option
- **Require password option**: `require_password` to force all notes to have a password
- **Key wrapping**: `enable_key_wrapping` and `wrapping_key` options to protect per-note keys
- **Privacy mode**: `privacy_mode` option to hide status details for missing/expired/invalid tokens
- **Secure deletion**: `secure_delete` option for SQLite secure_delete pragma + DELETE journal mode
- HMAC authentication for v1 CBC payloads (integrity verification)
- Backward compatibility for legacy encrypted data without version prefix

### Changed
- Default `encryption_method` changed from `AES-256-CBC` to `AES-256-GCM`
- Default `password_min_length` increased to 12 characters (was 8)
- `CryptNoteStandalone` now uses versioned encryption format (`v2:` or `v1:` prefix)
- Encrypted data format now includes version prefix for format identification
- Improved documentation with security best practices

### Security
- GCM mode provides authenticated encryption (AEAD) - detects tampering
- HMAC-SHA256 added for v1 CBC mode integrity verification
- Stronger default password requirements
- Optional key wrapping for defense in depth

## [0.1.0] - 2026-01-11

### Added
- Initial release
- `CryptNote` class with full database storage
  - Create encrypted notes with view limits (1-100 views)
  - Optional password protection using PBKDF2 (100,000 iterations)
  - Time-based expiration (up to 7 days)
  - Markdown and HTML content support
  - Automatic cleanup of old records
  - Secure deletion (data overwrite before delete)
  - Statistics API (`getStats()`)
- `CryptNoteStandalone` class for encryption-only usage
  - AES-256-CBC encryption/decryption
  - Password-protected encryption with PBKDF2
  - Token generation and validation
  - Secure password generation
  - Timing-safe string comparison
- SQLite storage with WAL mode
- Comprehensive documentation
- Example implementations
  - Basic usage examples
  - Standalone encryption examples
  - Complete web interface example
- PHPUnit test suite

### Requirements
- PHP 8.0+
- OpenSSL extension
- PDO extension with SQLite driver
