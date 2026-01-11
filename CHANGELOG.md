# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2026-01-11

### Added
- Initial release
- `CryptNote` class with full database storage
  - Create encrypted notes with view limits
  - Optional password protection using PBKDF2
  - Time-based expiration
  - Markdown and HTML content support
  - Automatic cleanup of old records
  - Secure deletion (data overwrite before delete)
  - Statistics API
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
