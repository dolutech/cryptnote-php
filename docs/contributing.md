# Contributing Guide

Thank you for your interest in contributing to the CryptNote PHP Library! This guide will help you get started.

## Table of Contents

- [Code of Conduct](#code-of-conduct)
- [Getting Started](#getting-started)
- [Development Setup](#development-setup)
- [Running Tests](#running-tests)
- [Code Style Guidelines](#code-style-guidelines)
- [Pull Request Process](#pull-request-process)
- [Reporting Issues](#reporting-issues)
- [Security Vulnerabilities](#security-vulnerabilities)

---

## Code of Conduct

By participating in this project, you agree to maintain a respectful and inclusive environment. We expect all contributors to:

- Be respectful and considerate
- Welcome newcomers and help them learn
- Focus on constructive feedback
- Accept responsibility for mistakes and learn from them

---

## Getting Started

### Prerequisites

- PHP 8.0 or higher
- Composer
- Git
- OpenSSL extension
- PDO extension with SQLite driver

### Fork and Clone

1. Fork the repository on GitHub
2. Clone your fork locally:

```bash
git clone https://github.com/YOUR_USERNAME/cryptnote-php.git
cd cryptnote-php
```

3. Add the upstream remote:

```bash
git remote add upstream https://github.com/dolutech/cryptnote-php.git
```

---

## Development Setup

### Install Dependencies

```bash
composer install
```

### Directory Structure

```
cryptnote-php/
├── src/
│   ├── CryptNote.php           # Main class with database storage
│   └── CryptNoteStandalone.php # Standalone encryption utilities
├── tests/
│   └── CryptNoteTest.php       # PHPUnit tests
├── examples/
│   ├── basic-usage.php         # Basic usage examples
│   ├── standalone-encryption.php
│   └── web-interface/          # Web interface example
├── docs/                       # Documentation
├── composer.json
├── phpunit.xml
└── README.md
```

### Create a Development Branch

```bash
git checkout -b feature/your-feature-name
```

---

## Running Tests

### Run All Tests

```bash
./vendor/bin/phpunit
```

### Run Specific Test File

```bash
./vendor/bin/phpunit tests/CryptNoteTest.php
```

### Run Specific Test Method

```bash
./vendor/bin/phpunit --filter testCreateSimpleNote
```

### Run Tests with Coverage

```bash
./vendor/bin/phpunit --coverage-html coverage/
```

Then open `coverage/index.html` in your browser.

### Test Configuration

Tests use a temporary SQLite database that is automatically cleaned up. The test configuration is in `phpunit.xml`:

```xml
<?xml version="1.0" encoding="UTF-8"?>
<phpunit bootstrap="vendor/autoload.php"
         colors="true"
         verbose="true">
    <testsuites>
        <testsuite name="CryptNote Test Suite">
            <directory>tests</directory>
        </testsuite>
    </testsuites>
</phpunit>
```

### Writing Tests

When adding new features, include tests:

```php
<?php
namespace CryptNote\Tests;

use PHPUnit\Framework\TestCase;
use CryptNote\CryptNote;

class YourFeatureTest extends TestCase
{
    private CryptNote $cryptnote;
    private string $testDbPath;

    protected function setUp(): void
    {
        $this->testDbPath = sys_get_temp_dir() . '/cryptnote_test_' . uniqid() . '.db';
        $this->cryptnote = new CryptNote([
            'db_path' => $this->testDbPath,
            'auto_cleanup' => false,
        ]);
    }

    protected function tearDown(): void
    {
        // Clean up test database
        @unlink($this->testDbPath);
        @unlink($this->testDbPath . '-wal');
        @unlink($this->testDbPath . '-shm');
    }

    public function testYourFeature(): void
    {
        // Arrange
        $content = 'Test content';
        
        // Act
        $result = $this->cryptnote->create($content);
        
        // Assert
        $this->assertTrue($result['success']);
        $this->assertNotEmpty($result['token']);
    }
}
```

---

## Code Style Guidelines

### PHP Standards

We follow PSR-12 coding standards with some additions:

#### Naming Conventions

```php
// Classes: PascalCase
class CryptNote { }
class CryptNoteStandalone { }

// Methods: camelCase
public function createNote() { }
private function validateToken() { }

// Variables: camelCase
$encryptedData = '';
$maxViews = 1;

// Constants: UPPER_SNAKE_CASE
const MAX_TOKEN_LENGTH = 64;
```

#### Type Declarations

Always use type declarations:

```php
// ✅ Good
public function create(string $content, array $options = []): array
{
    // ...
}

// ❌ Bad
public function create($content, $options = [])
{
    // ...
}
```

#### Documentation

Use PHPDoc for all public methods:

```php
/**
 * Create an encrypted note.
 *
 * @param string $content The content to encrypt
 * @param array $options Creation options:
 *   - password: Optional password for protection
 *   - max_views: Maximum views (1-100)
 *   - expire_minutes: Minutes until expiration
 * @return array Contains 'token', 'has_password', etc.
 * @throws Exception If content is empty or exceeds max length
 */
public function create(string $content, array $options = []): array
{
    // ...
}
```

#### Error Handling

Use exceptions for error conditions:

```php
// ✅ Good
if (empty($content)) {
    throw new Exception('Content cannot be empty');
}

// ❌ Bad
if (empty($content)) {
    return ['error' => 'Content cannot be empty'];
}
```

### Code Formatting

#### Indentation

Use 4 spaces for indentation (no tabs).

#### Line Length

Keep lines under 120 characters when possible.

#### Braces

Use Allman style for classes, K&R for methods:

```php
class CryptNote
{
    public function create(string $content): array
    {
        if ($condition) {
            // ...
        }
    }
}
```

#### Arrays

Use short array syntax:

```php
// ✅ Good
$options = [
    'password' => null,
    'max_views' => 1,
];

// ❌ Bad
$options = array(
    'password' => null,
    'max_views' => 1,
);
```

### Static Analysis

Run static analysis before submitting:

```bash
# If PHPStan is installed
./vendor/bin/phpstan analyse src tests

# If Psalm is installed
./vendor/bin/psalm
```

---

## Pull Request Process

### Before Submitting

1. **Update your fork**:
   ```bash
   git fetch upstream
   git rebase upstream/main
   ```

2. **Run tests**:
   ```bash
   ./vendor/bin/phpunit
   ```

3. **Check code style**:
   ```bash
   # Manual review or use PHP_CodeSniffer
   ./vendor/bin/phpcs --standard=PSR12 src/
   ```

4. **Update documentation** if needed

### Submitting a Pull Request

1. Push your branch:
   ```bash
   git push origin feature/your-feature-name
   ```

2. Open a Pull Request on GitHub

3. Fill out the PR template:

```markdown
## Description
Brief description of changes

## Type of Change
- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update

## Testing
- [ ] Tests pass locally
- [ ] New tests added for new features
- [ ] Documentation updated

## Checklist
- [ ] Code follows style guidelines
- [ ] Self-reviewed code
- [ ] Commented complex code
- [ ] No new warnings
```

### Review Process

1. Maintainers will review your PR
2. Address any feedback
3. Once approved, your PR will be merged

### After Merge

```bash
# Update your local main
git checkout main
git pull upstream main

# Delete your feature branch
git branch -d feature/your-feature-name
git push origin --delete feature/your-feature-name
```

---

## Reporting Issues

### Bug Reports

When reporting bugs, include:

1. **PHP version**: `php -v`
2. **Library version**: Check `composer.json`
3. **Operating system**
4. **Steps to reproduce**
5. **Expected behavior**
6. **Actual behavior**
7. **Error messages** (if any)

Use this template:

```markdown
## Bug Description
Clear description of the bug

## Environment
- PHP Version: 8.2.0
- Library Version: 1.0.0
- OS: Ubuntu 22.04

## Steps to Reproduce
1. Initialize CryptNote with...
2. Call create() with...
3. See error

## Expected Behavior
What should happen

## Actual Behavior
What actually happens

## Error Messages
```
Paste any error messages here
```

## Additional Context
Any other relevant information
```

### Feature Requests

For feature requests, include:

1. **Use case**: Why is this feature needed?
2. **Proposed solution**: How should it work?
3. **Alternatives considered**: Other approaches you've thought of
4. **Additional context**: Examples, mockups, etc.

---

## Security Vulnerabilities

**Do not report security vulnerabilities through public issues.**

Instead:

1. Email: contato@dolutech.com
2. Include:
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact
   - Suggested fix (if any)

We will respond within 48 hours and work with you to address the issue.

---

## Development Tips

### Debugging

```php
// Enable error reporting during development
error_reporting(E_ALL);
ini_set('display_errors', '1');

// Use var_dump for quick debugging
var_dump($result);

// Or use a debugger like Xdebug
```

### Testing Encryption

```php
// Test encryption/decryption manually
$crypto = new CryptNoteStandalone();
$key = $crypto->generateKey();

$original = "Test message";
$encrypted = $crypto->encrypt($original, $key);
$decrypted = $crypto->decrypt($encrypted, $key);

assert($original === $decrypted, "Encryption/decryption failed");
```

### Database Inspection

```bash
# View database contents (for debugging)
sqlite3 /path/to/cryptnote.db

sqlite> .tables
sqlite> .schema encrypted_content
sqlite> SELECT token, has_password, remaining_views FROM encrypted_content;
```

---

## Recognition

Contributors will be recognized in:

- The project README
- Release notes
- The contributors page on GitHub

Thank you for contributing to CryptNote! 🔐

---

## See Also

- [API Reference](api-reference.md)
- [Security Guide](security.md)
- [Examples](examples.md)
