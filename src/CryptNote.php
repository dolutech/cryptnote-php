<?php
/**
 * CryptNote - Secure Message Encryption Library
 * 
 * A standalone PHP library for creating encrypted, self-destructing messages
 * with view limits and optional password protection.
 * 
 * @package CryptNote
 * @version 1.0.0
 * @license MIT
 * @link https://github.com/dolutech/cryptnote-php
 */

namespace CryptNote;

use Exception;
use PDO;
use PDOException;
use DateTime;
use DateTimeZone;
use DateInterval;

class CryptNote
{
    private PDO $db;
    private array $config;

    /**
     * Initialize CryptNote with configuration options.
     *
     * @param array $config Configuration options:
     *   - db_path: Path to SQLite database file (default: ./cryptnote.db)
     *   - encryption_method: OpenSSL cipher method (default: AES-256-CBC)
     *   - token_length: Length of generated tokens in bytes (default: 32)
     *   - max_content_length: Maximum content length in characters (default: 50000)
     *   - pbkdf2_iterations: PBKDF2 iterations for password derivation (default: 10000)
     *   - auto_cleanup: Enable automatic cleanup of old records (default: true)
     *   - cleanup_days: Days after which unviewed records are cleaned (default: 15)
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'db_path' => __DIR__ . '/../data/cryptnote.db',
            'encryption_method' => 'AES-256-CBC',
            'token_length' => 32,
            'max_content_length' => 50000,
            'pbkdf2_iterations' => 100000,
            'auto_cleanup' => true,
            'cleanup_days' => 15,
        ], $config);

        // Validate encryption method
        $validMethods = openssl_get_cipher_methods();
        if (!in_array($this->config['encryption_method'], $validMethods, true)) {
            throw new Exception('Invalid encryption method: ' . $this->config['encryption_method']);
        }

        $this->initDatabase();

        if ($this->config['auto_cleanup']) {
            $this->maybeCleanup();
        }
    }

    /**
     * Create an encrypted note.
     *
     * @param string $content The content to encrypt
     * @param array $options Options:
     *   - password: Optional password for additional protection
     *   - max_views: Maximum number of views (1-100, default: 1)
     *   - expire_minutes: Minutes until expiration (null for no expiration)
     *   - is_markdown: Whether content is Markdown (default: false)
     *   - is_html: Whether content is HTML (default: false)
     * @return array Contains 'token', 'share_url' (if base_url set), and metadata
     * @throws Exception If content is empty or exceeds max length
     */
    public function create(string $content, array $options = []): array
    {
        $content = trim($content);
        
        if (empty($content)) {
            throw new Exception('Content cannot be empty');
        }

        if (strlen($content) > $this->config['max_content_length']) {
            throw new Exception('Content exceeds maximum length of ' . $this->config['max_content_length'] . ' characters');
        }

        $password = $options['password'] ?? null;
        $maxViews = max(1, min(100, (int)($options['max_views'] ?? 1)));
        $expireMinutes = $options['expire_minutes'] ?? null;
        $isMarkdown = (bool)($options['is_markdown'] ?? false);
        $isHtml = (bool)($options['is_html'] ?? false);

        if ($isHtml) {
            $isMarkdown = false;
        }

        // Validate password if provided
        $hasPassword = false;
        if ($password !== null && $password !== '') {
            if (strlen($password) < 6) {
                throw new Exception('Password must be at least 6 characters');
            }
            if (strlen($password) > 100) {
                throw new Exception('Password cannot exceed 100 characters');
            }
            $hasPassword = true;
        }

        // Calculate expiration
        $expiresAt = null;
        if ($expireMinutes !== null) {
            $expireMinutes = max(1, min(10080, (int)$expireMinutes)); // Max 7 days
            $expiresAt = (new DateTime('now', new DateTimeZone('UTC')))
                ->add(new DateInterval('PT' . $expireMinutes . 'M'))
                ->format('Y-m-d H:i:s');
        }

        // Generate unique token
        $token = $this->generateToken();
        $attempts = 0;
        while ($this->tokenExists($token) && $attempts < 10) {
            $token = $this->generateToken();
            $attempts++;
        }

        if ($attempts >= 10) {
            throw new Exception('Failed to generate unique token');
        }

        // Generate encryption key and encrypt content
        $encryptionKey = $this->generateEncryptionKey();
        
        if ($hasPassword) {
            $encryptedData = $this->encryptWithPassword($content, $encryptionKey, $password);
        } else {
            $encryptedData = $this->encrypt($content, $encryptionKey);
        }

        // Store in database
        $this->store($token, $encryptedData, $encryptionKey, $hasPassword, $maxViews, $isMarkdown, $isHtml, $expiresAt);

        $result = [
            'success' => true,
            'token' => $token,
            'has_password' => $hasPassword,
            'max_views' => $maxViews,
            'is_markdown' => $isMarkdown,
            'is_html' => $isHtml,
            'expires_at' => $expiresAt,
            'created_at' => (new DateTime('now', new DateTimeZone('UTC')))->format('Y-m-d H:i:s'),
        ];

        if (isset($this->config['base_url'])) {
            $result['share_url'] = rtrim($this->config['base_url'], '/') . '?token=' . $token;
        }

        return $result;
    }

    /**
     * View and decrypt a note.
     *
     * @param string $token The note token
     * @param string|null $password Password if required
     * @return array Contains 'content', 'remaining_views', and metadata
     * @throws Exception If note not found, expired, or password incorrect
     */
    public function view(string $token, ?string $password = null): array
    {
        if (!$this->validateTokenFormat($token)) {
            throw new Exception('Invalid token format');
        }

        $record = $this->getRecord($token);

        if (!$record) {
            throw new Exception('Note not found or expired');
        }

        $hasPassword = (bool)$record['has_password'];
        $isMarkdown = (bool)$record['is_markdown'];
        $isHtml = (bool)($record['is_html'] ?? false);

        if ($isHtml) {
            $isMarkdown = false;
        }

        // Decrypt content
        if ($hasPassword) {
            if ($password === null || $password === '') {
                throw new Exception('Password required');
            }
            try {
                $content = $this->decryptWithPassword($record['encrypted_data'], $record['encryption_key'], $password);
            } catch (Exception $e) {
                throw new Exception('Incorrect password');
            }
        } else {
            $content = $this->decrypt($record['encrypted_data'], $record['encryption_key']);
        }

        // Decrement views and delete if necessary
        $remainingViews = $this->decrementViews($token);
        
        if ($remainingViews <= 0) {
            $this->secureDelete($token);
        }

        return [
            'success' => true,
            'content' => $content,
            'is_markdown' => $isMarkdown,
            'is_html' => $isHtml,
            'remaining_views' => max(0, $remainingViews),
            'max_views' => (int)$record['max_views'],
            'expires_at' => $record['expires_at'] ?? null,
            'destroyed' => $remainingViews <= 0,
        ];
    }

    /**
     * Check the status of a note without viewing it.
     *
     * @param string $token The note token
     * @return array Status information
     */
    public function status(string $token): array
    {
        if (!$this->validateTokenFormat($token)) {
            return ['success' => true, 'status' => 'invalid_token'];
        }

        $sql = "SELECT has_password, is_markdown, is_html, max_views, remaining_views, expires_at, created_at 
                FROM encrypted_content WHERE token = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$token]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$record) {
            return ['success' => true, 'status' => 'not_found'];
        }

        // Check expiration
        $now = new DateTime('now', new DateTimeZone('UTC'));
        $expiredByTime = false;
        if (!empty($record['expires_at'])) {
            $expiredByTime = (new DateTime($record['expires_at'], new DateTimeZone('UTC'))) <= $now;
        }
        $expiredByViews = ((int)$record['remaining_views']) <= 0;
        $status = ($expiredByTime || $expiredByViews) ? 'expired' : 'active';

        return [
            'success' => true,
            'status' => $status,
            'requires_password' => (bool)$record['has_password'],
            'is_markdown' => (bool)$record['is_markdown'],
            'is_html' => (bool)($record['is_html'] ?? false),
            'max_views' => (int)$record['max_views'],
            'remaining_views' => (int)$record['remaining_views'],
            'expires_at' => $record['expires_at'] ?? null,
            'created_at' => $record['created_at'] ?? null,
        ];
    }

    /**
     * Manually delete a note.
     *
     * @param string $token The note token
     * @return bool True if deleted
     */
    public function delete(string $token): bool
    {
        if (!$this->validateTokenFormat($token)) {
            return false;
        }
        return $this->secureDelete($token);
    }

    // ==================== ENCRYPTION METHODS ====================

    /**
     * Generate a secure random token.
     */
    private function generateToken(): string
    {
        $length = $this->config['token_length'];
        $entropy = random_bytes($length) . 
                   hash('sha256', microtime(true) . getmypid() . uniqid('', true), true) .
                   random_bytes($length);
        
        $finalHash = hash('sha256', $entropy, true);
        return bin2hex(substr($finalHash, 0, $length));
    }

    /**
     * Generate a random encryption key.
     */
    private function generateEncryptionKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Encrypt content using AES-256-CBC.
     */
    private function encrypt(string $data, string $key): string
    {
        $method = $this->config['encryption_method'];
        $iv = random_bytes(16);
        
        $encrypted = openssl_encrypt($data, $method, base64_decode($key), OPENSSL_RAW_DATA, $iv);
        
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        
        return base64_encode($iv . $encrypted);
    }

    /**
     * Encrypt content with password using AES-256-CBC and PBKDF2.
     */
    private function encryptWithPassword(string $data, string $key, string $password): string
    {
        $salt = random_bytes(16);
        $iterations = $this->config['pbkdf2_iterations'];
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $finalKey = base64_encode($combinedKey);
        
        $method = $this->config['encryption_method'];
        $iv = random_bytes(16);
        
        $encrypted = openssl_encrypt($data, $method, base64_decode($finalKey), OPENSSL_RAW_DATA, $iv);
        
        if ($encrypted === false) {
            throw new Exception('Encryption with password failed');
        }
        
        return base64_encode($salt . $iv . $encrypted);
    }

    /**
     * Decrypt content using AES-256-CBC.
     */
    private function decrypt(string $encryptedData, string $key): string
    {
        $method = $this->config['encryption_method'];
        $data = base64_decode($encryptedData);
        
        if ($data === false || strlen($data) < 16) {
            throw new Exception('Invalid encrypted data');
        }
        
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        $decrypted = openssl_decrypt($encrypted, $method, base64_decode($key), OPENSSL_RAW_DATA, $iv);
        
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        
        return $decrypted;
    }

    /**
     * Decrypt content with password using AES-256-CBC and PBKDF2.
     */
    private function decryptWithPassword(string $encryptedData, string $key, string $password): string
    {
        $method = $this->config['encryption_method'];
        $data = base64_decode($encryptedData);
        
        if ($data === false || strlen($data) < 32) {
            throw new Exception('Invalid encrypted data');
        }
        
        $salt = substr($data, 0, 16);
        $iv = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        
        $iterations = $this->config['pbkdf2_iterations'];
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $finalKey = base64_encode($combinedKey);
        
        $decrypted = openssl_decrypt($encrypted, $method, base64_decode($finalKey), OPENSSL_RAW_DATA, $iv);
        
        if ($decrypted === false) {
            throw new Exception('Decryption with password failed');
        }
        
        return $decrypted;
    }

    // ==================== DATABASE METHODS ====================

    /**
     * Initialize SQLite database.
     */
    private function initDatabase(): void
    {
        $dbPath = $this->config['db_path'];
        $dbDir = dirname($dbPath);
        
        if (!is_dir($dbDir)) {
            mkdir($dbDir, 0700, true);
        }

        try {
            $this->db = new PDO('sqlite:' . $dbPath);
            $this->db->setAttribute(PDO::ATTR_ERRMODE, PDO::ERRMODE_EXCEPTION);
            $this->db->setAttribute(PDO::ATTR_DEFAULT_FETCH_MODE, PDO::FETCH_ASSOC);
            
            $this->db->exec('PRAGMA foreign_keys = ON');
            $this->db->exec('PRAGMA journal_mode = WAL');
            $this->db->exec('PRAGMA synchronous = FULL');

            $this->createTables();
        } catch (PDOException $e) {
            throw new Exception('Database connection failed: ' . $e->getMessage());
        }
    }

    /**
     * Create database tables.
     */
    private function createTables(): void
    {
        $sql = "
            CREATE TABLE IF NOT EXISTS encrypted_content (
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
            )
        ";
        $this->db->exec($sql);
        
        $this->db->exec("CREATE INDEX IF NOT EXISTS idx_created_at ON encrypted_content(created_at)");
        $this->db->exec("CREATE INDEX IF NOT EXISTS idx_expires_at ON encrypted_content(expires_at)");
    }

    /**
     * Validate token format.
     */
    private function validateTokenFormat(string $token): bool
    {
        return is_string($token) && strlen($token) === 64 && preg_match('/^[a-f0-9]{64}$/i', $token);
    }

    /**
     * Check if token exists.
     */
    private function tokenExists(string $token): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM encrypted_content WHERE token = ?");
        $stmt->execute([$token]);
        return $stmt->fetch() !== false;
    }

    /**
     * Store encrypted content.
     */
    private function store(string $token, string $encryptedData, string $encryptionKey, bool $hasPassword, int $maxViews, bool $isMarkdown, bool $isHtml, ?string $expiresAt): void
    {
        $sql = "INSERT INTO encrypted_content (token, encrypted_data, encryption_key, has_password, is_markdown, is_html, max_views, remaining_views, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$token, $encryptedData, $encryptionKey, $hasPassword ? 1 : 0, $isMarkdown ? 1 : 0, $isHtml ? 1 : 0, $maxViews, $maxViews, $expiresAt]);
    }

    /**
     * Get record by token.
     */
    private function getRecord(string $token): ?array
    {
        $sql = "SELECT * FROM encrypted_content 
                WHERE token = ? AND remaining_views > 0 
                AND (expires_at IS NULL OR expires_at > datetime('now'))";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$token]);
        $record = $stmt->fetch();
        return $record ?: null;
    }

    /**
     * Decrement remaining views.
     */
    private function decrementViews(string $token): int
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare("SELECT remaining_views FROM encrypted_content WHERE token = ?");
            $stmt->execute([$token]);
            $row = $stmt->fetch();
            
            if (!$row) {
                $this->db->rollBack();
                return 0;
            }
            
            $newRemaining = max(0, (int)$row['remaining_views'] - 1);
            
            $stmt = $this->db->prepare("UPDATE encrypted_content SET remaining_views = ? WHERE token = ?");
            $stmt->execute([$newRemaining, $token]);
            
            $this->db->commit();
            return $newRemaining;
        } catch (PDOException $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    /**
     * Securely delete a record.
     */
    private function secureDelete(string $token): bool
    {
        try {
            // Overwrite with random data first
            $randomData = base64_encode(random_bytes(1024));
            $randomKey = base64_encode(random_bytes(64));
            
            $stmt = $this->db->prepare("UPDATE encrypted_content SET encrypted_data = ?, encryption_key = ? WHERE token = ?");
            $stmt->execute([$randomData, $randomKey, $token]);
            
            // Then delete
            $stmt = $this->db->prepare("DELETE FROM encrypted_content WHERE token = ?");
            $stmt->execute([$token]);
            
            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

    /**
     * Cleanup old records.
     */
    private function maybeCleanup(): void
    {
        $dbDir = dirname($this->config['db_path']);
        $marker = $dbDir . '/.cleanup.touch';
        $now = time();
        
        if (file_exists($marker) && ($now - filemtime($marker)) < 86400) {
            return;
        }

        try {
            $days = max(1, (int)$this->config['cleanup_days']);
            
            // Use prepared statement to avoid SQL injection
            $stmt = $this->db->prepare("DELETE FROM encrypted_content 
                    WHERE expires_at IS NULL 
                    AND remaining_views = max_views 
                    AND created_at < datetime('now', '-' || ? || ' days')");
            $stmt->execute([$days]);
            $deleted = $stmt->rowCount();
            
            // Also delete expired records
            $this->db->exec("DELETE FROM encrypted_content WHERE expires_at IS NOT NULL AND expires_at < datetime('now')");
            
            @touch($marker, $now);
            
            if ($deleted > 0) {
                $this->db->exec('VACUUM');
            }
        } catch (PDOException $e) {
            // Silently fail cleanup
        }
    }

    /**
     * Get database statistics.
     */
    public function getStats(): array
    {
        $stats = [];
        
        $result = $this->db->query('SELECT COUNT(*) FROM encrypted_content');
        $stats['total_notes'] = (int)$result->fetchColumn();
        
        $result = $this->db->query('SELECT COUNT(*) FROM encrypted_content WHERE remaining_views = max_views');
        $stats['unviewed_notes'] = (int)$result->fetchColumn();
        
        $result = $this->db->query('SELECT COUNT(*) FROM encrypted_content WHERE has_password = 1');
        $stats['password_protected'] = (int)$result->fetchColumn();
        
        $result = $this->db->query("SELECT COUNT(*) FROM encrypted_content WHERE expires_at IS NOT NULL AND expires_at > datetime('now')");
        $stats['with_expiration'] = (int)$result->fetchColumn();
        
        return $stats;
    }
}
