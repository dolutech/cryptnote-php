# Migration Guide

Version history, breaking changes, and migration guides for the CryptNote PHP Library.

## Table of Contents

- [Version History](#version-history)
- [Upgrade Guides](#upgrade-guides)
- [Breaking Changes](#breaking-changes)
- [Deprecation Notices](#deprecation-notices)
- [Database Migrations](#database-migrations)

---

## Version History

### Version 1.0.0 (Current)

**Release Date**: 2026

**Features**:
- Initial public release
- AES-256-CBC encryption
- PBKDF2 password protection (100,000 iterations default)
- SQLite storage with WAL mode
- View limits (1-100 views)
- Time expiration (up to 7 days)
- Markdown and HTML content support
- Automatic cleanup of old records
- Secure deletion (overwrite before delete)
- Standalone encryption utilities

**Requirements**:
- PHP 8.0+
- OpenSSL extension
- PDO extension with SQLite driver

---

## Upgrade Guides

### Upgrading from Pre-Release Versions

If you were using a pre-release or development version, follow these steps:

#### Step 1: Backup Your Database

```bash
cp /path/to/cryptnote.db /path/to/cryptnote.db.backup
```

#### Step 2: Update the Library

```bash
composer update dolutech/cryptnote-php
```

#### Step 3: Run Database Migration

```php
<?php
// migration-1.0.php
use CryptNote\CryptNote;

// Initialize with your existing database
$cryptnote = new CryptNote([
    'db_path' => '/path/to/cryptnote.db',
]);

// The library will automatically create any missing columns
// Check if is_html column exists and add if needed
$db = new PDO('sqlite:/path/to/cryptnote.db');

$result = $db->query("PRAGMA table_info(encrypted_content)");
$columns = array_column($result->fetchAll(PDO::FETCH_ASSOC), 'name');

if (!in_array('is_html', $columns)) {
    $db->exec("ALTER TABLE encrypted_content ADD COLUMN is_html BOOLEAN DEFAULT FALSE");
    echo "Added is_html column\n";
}

echo "Migration complete!\n";
```

#### Step 4: Update Your Code

```php
// Old way (if you were using different method names)
// $result = $cryptnote->createNote($content);

// New way (v1.0.0)
$result = $cryptnote->create($content);
```

---

## Breaking Changes

### Version 1.0.0

#### Configuration Changes

| Old Key | New Key | Notes |
|---------|---------|-------|
| `database_path` | `db_path` | Renamed for consistency |
| `iterations` | `pbkdf2_iterations` | More descriptive name |
| `max_length` | `max_content_length` | Clarified purpose |

**Migration:**

```php
// Old configuration
$cryptnote = new CryptNote([
    'database_path' => '/path/to/db.sqlite',
    'iterations' => 10000,
    'max_length' => 50000,
]);

// New configuration (v1.0.0)
$cryptnote = new CryptNote([
    'db_path' => '/path/to/db.sqlite',
    'pbkdf2_iterations' => 100000,  // Note: default increased
    'max_content_length' => 50000,
]);
```

#### Default Value Changes

| Setting | Old Default | New Default | Reason |
|---------|-------------|-------------|--------|
| `pbkdf2_iterations` | 10,000 | 100,000 | Improved security |
| `cleanup_days` | 30 | 15 | Faster cleanup |

**Impact**: Password-protected notes created with the old default will still work, but new notes will use more iterations.

#### Method Signature Changes

##### `create()` Method

```php
// Old signature
public function create(string $content, ?string $password = null, int $maxViews = 1): array

// New signature (v1.0.0)
public function create(string $content, array $options = []): array
```

**Migration:**

```php
// Old way
$result = $cryptnote->create('content', 'password123', 5);

// New way (v1.0.0)
$result = $cryptnote->create('content', [
    'password' => 'password123',
    'max_views' => 5,
]);
```

##### `view()` Method

No changes to the `view()` method signature.

#### Return Value Changes

##### `create()` Return Value

```php
// Old return value
[
    'token' => 'abc123...',
    'password_protected' => true,
]

// New return value (v1.0.0)
[
    'success' => true,
    'token' => 'abc123...',
    'has_password' => true,
    'max_views' => 5,
    'is_markdown' => false,
    'is_html' => false,
    'expires_at' => '2026-01-15 12:00:00',
    'created_at' => '2026-01-15 11:00:00',
    'share_url' => 'https://...',  // if base_url configured
]
```

**Migration:**

```php
// Old way
if ($result['password_protected']) { ... }

// New way (v1.0.0)
if ($result['has_password']) { ... }
```

##### `status()` Return Value

```php
// Old return value
[
    'exists' => true,
    'needs_password' => true,
    'views_left' => 3,
]

// New return value (v1.0.0)
[
    'success' => true,
    'status' => 'active',
    'requires_password' => true,
    'is_markdown' => false,
    'is_html' => false,
    'max_views' => 5,
    'remaining_views' => 3,
    'expires_at' => null,
    'created_at' => '2026-01-15 11:00:00',
]
```

---

## Deprecation Notices

### Planned Deprecations for v2.0

The following features are planned for deprecation in version 2.0:

1. **SQLite as default storage**: Will be replaced with a storage interface
2. **Direct database access**: Use the provided methods instead
3. **`getStats()` method**: Will be moved to a separate admin class

### Migration Preparation

To prepare for v2.0, avoid:

```php
// ❌ Avoid direct database access
$db = new PDO('sqlite:' . $config['db_path']);
$db->query("SELECT * FROM encrypted_content");

// ✅ Use provided methods
$stats = $cryptnote->getStats();
$status = $cryptnote->status($token);
```

---

## Database Migrations

### Schema Changes

#### v1.0.0 Schema

```sql
CREATE TABLE encrypted_content (
    token VARCHAR(64) PRIMARY KEY,
    encrypted_data TEXT NOT NULL,
    encryption_key VARCHAR(64) NOT NULL,
    has_password BOOLEAN DEFAULT FALSE,
    is_markdown BOOLEAN DEFAULT FALSE,
    is_html BOOLEAN DEFAULT FALSE,
    max_views INTEGER NOT NULL DEFAULT 1,
    remaining_views INTEGER NOT NULL DEFAULT 1,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    expires_at DATETIME NULL
);

CREATE INDEX idx_created_at ON encrypted_content(created_at);
CREATE INDEX idx_expires_at ON encrypted_content(expires_at);
```

### Manual Migration Scripts

#### Adding Missing Columns

```php
<?php
// add-missing-columns.php

$dbPath = '/path/to/cryptnote.db';
$db = new PDO('sqlite:' . $dbPath);
$db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);

// Get existing columns
$result = $db->query("PRAGMA table_info(encrypted_content)");
$columns = array_column($result->fetchAll(PDO::FETCH_ASSOC), 'name');

// Add is_html if missing
if (!in_array('is_html', $columns)) {
    $db->exec("ALTER TABLE encrypted_content ADD COLUMN is_html BOOLEAN DEFAULT FALSE");
    echo "Added is_html column\n";
}

// Add is_markdown if missing
if (!in_array('is_markdown', $columns)) {
    $db->exec("ALTER TABLE encrypted_content ADD COLUMN is_markdown BOOLEAN DEFAULT FALSE");
    echo "Added is_markdown column\n";
}

// Add expires_at if missing
if (!in_array('expires_at', $columns)) {
    $db->exec("ALTER TABLE encrypted_content ADD COLUMN expires_at DATETIME NULL");
    $db->exec("CREATE INDEX IF NOT EXISTS idx_expires_at ON encrypted_content(expires_at)");
    echo "Added expires_at column and index\n";
}

echo "Migration complete!\n";
```

#### Rebuilding Indexes

```php
<?php
// rebuild-indexes.php

$dbPath = '/path/to/cryptnote.db';
$db = new PDO('sqlite:' . $dbPath);

// Drop and recreate indexes
$db->exec("DROP INDEX IF EXISTS idx_created_at");
$db->exec("DROP INDEX IF EXISTS idx_expires_at");

$db->exec("CREATE INDEX idx_created_at ON encrypted_content(created_at)");
$db->exec("CREATE INDEX idx_expires_at ON encrypted_content(expires_at)");

// Optimize database
$db->exec("VACUUM");
$db->exec("ANALYZE");

echo "Indexes rebuilt and database optimized!\n";
```

#### Exporting Data for Backup

```php
<?php
// export-notes.php

$dbPath = '/path/to/cryptnote.db';
$db = new PDO('sqlite:' . $dbPath);

$stmt = $db->query("SELECT * FROM encrypted_content");
$notes = $stmt->fetchAll(PDO::FETCH_ASSOC);

// Export to JSON (encrypted data remains encrypted)
file_put_contents(
    'notes-backup-' . date('Y-m-d') . '.json',
    json_encode($notes, JSON_PRETTY_PRINT)
);

echo "Exported " . count($notes) . " notes\n";
```

---

## Compatibility Matrix

| PHP Version | Library Version | Support Status |
|-------------|-----------------|----------------|
| 8.0 | 1.0.x | ✅ Supported |
| 8.1 | 1.0.x | ✅ Supported |
| 8.2 | 1.0.x | ✅ Supported |
| 8.3 | 1.0.x | ✅ Supported |
| 7.4 | - | ❌ Not supported |

---

## Getting Help

If you encounter issues during migration:

1. **Check the documentation**: Review the [API Reference](api-reference.md)
2. **Search issues**: Look for similar issues on [GitHub](https://github.com/dolutech/cryptnote-php/issues)
3. **Open an issue**: Provide your PHP version, library version, and error messages
4. **Community support**: Join discussions on GitHub

---

## See Also

- [API Reference](api-reference.md)
- [Configuration Guide](configuration.md)
- [Contributing Guide](contributing.md)
