<?php
/**
 * CryptNote - Secure Message Encryption Library
 *
 * A standalone PHP library for creating encrypted, self-destructing messages
 * with view limits and optional password protection.
 *
 * @package CryptNote
 * @version 0.2.0
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
    private const FORMAT_V1 = 'v1'; // CBC + HMAC
    private const FORMAT_V2 = 'v2'; // GCM (AEAD)

    private PDO $db;
    private array $config;
    private string $encryptionVersion;

    /**
     * Initialize CryptNote with configuration options.
     *
     * @param array $config Configuration options:
     *   - db_path: Path to SQLite database file (default: ./cryptnote.db)
     *   - encryption_method: OpenSSL cipher method (default: AES-256-GCM)
     *   - token_length: Length of generated tokens in bytes (default: 32)
     *   - max_content_length: Maximum content length in characters (default: 50000)
     *   - pbkdf2_iterations: PBKDF2 iterations for password derivation (default: 100000)
     *   - auto_cleanup: Enable automatic cleanup of old records (default: true)
     *   - cleanup_days: Days after which unviewed records are cleaned (default: 15)
     *   - encryption_version: v2 (AEAD) or v1 (legacy)
     *   - enable_key_wrapping: Whether to wrap per-note keys with a wrapping key
     *   - wrapping_key: App-provided wrapping key (string)
     *   - password_min_length: Minimum password length (default: 12)
     *   - password_validator: Optional callable validator
     *   - privacy_mode: If true, status() returns not_found for missing/expired/invalid
     *   - require_password: If true, all notes must have password
     *   - secure_delete: If true, use delete journal mode and secure_delete pragma
     */
    public function __construct(array $config = [])
    {
        $this->config = array_merge([
            'db_path' => __DIR__ . '/../data/cryptnote.db',
            'encryption_method' => 'AES-256-GCM',
            'token_length' => 32,
            'max_content_length' => 50000,
            'pbkdf2_iterations' => 100000,
            'auto_cleanup' => true,
            'cleanup_days' => 15,
            'encryption_version' => self::FORMAT_V2,
            'enable_key_wrapping' => false,
            'wrapping_key' => null,
            'password_min_length' => 12,
            'password_validator' => null,
            'privacy_mode' => false,
            'require_password' => false,
            'secure_delete' => false,
        ], $config);

        // Validate encryption method (case-insensitive comparison)
        $validMethods = array_map('strtolower', openssl_get_cipher_methods());
        if (!in_array(strtolower($this->config['encryption_method']), $validMethods, true)) {
            throw new Exception('Invalid encryption method: ' . $this->config['encryption_method']);
        }

        $this->encryptionVersion = $this->config['encryption_version'] === self::FORMAT_V1 ? self::FORMAT_V1 : self::FORMAT_V2;

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

        // Validate password if provided or required
        $hasPassword = false;
        if ($password !== null && $password !== '') {
            $minLen = (int)$this->config['password_min_length'];
            if (strlen($password) < $minLen) {
                throw new Exception('Password must be at least ' . $minLen . ' characters');
            }
            if (strlen($password) > 100) {
                throw new Exception('Password cannot exceed 100 characters');
            }
            if (is_callable($this->config['password_validator'])) {
                $validator = $this->config['password_validator'];
                $isValid = $validator($password);
                if ($isValid === false) {
                    throw new Exception('Password does not meet policy requirements');
                }
            }
            $hasPassword = true;
        } elseif ($this->config['require_password']) {
            throw new Exception('Password is required by configuration');
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
        $rawEncryptionKey = $this->generateEncryptionKey();
        $storedEncryptionKey = $rawEncryptionKey;

        if ($this->config['enable_key_wrapping'] && $this->config['wrapping_key']) {
            $storedEncryptionKey = $this->wrapKey($rawEncryptionKey, $this->config['wrapping_key']);
        }
        
        if ($hasPassword) {
            $encryptedData = $this->encryptWithPassword($content, $rawEncryptionKey, $password);
        } else {
            $encryptedData = $this->encryptPayload($content, $rawEncryptionKey);
        }

        // Store in database
        $this->store($token, $encryptedData, $storedEncryptionKey, $hasPassword, $maxViews, $isMarkdown, $isHtml, $expiresAt);

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

        $storedKey = $record['encryption_key'];
        if ($this->config['enable_key_wrapping'] && $this->config['wrapping_key']) {
            $storedKey = $this->unwrapKey($storedKey, $this->config['wrapping_key']);
        }

        // Decrypt content
        if ($hasPassword) {
            if ($password === null || $password === '') {
                throw new Exception('Password required');
            }
            try {
                $content = $this->decryptWithPassword($record['encrypted_data'], $storedKey, $password);
            } catch (Exception $e) {
                throw new Exception('Incorrect password');
            }
        } else {
            $content = $this->decryptPayload($record['encrypted_data'], $storedKey);
        }

        // Decrement views atomically and delete if necessary
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
            return ['success' => true, 'status' => $this->config['privacy_mode'] ? 'not_found' : 'invalid_token'];
        }

        $sql = "SELECT has_password, is_markdown, is_html, max_views, remaining_views, expires_at, created_at 
                FROM encrypted_content WHERE token = ?";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$token]);
        $record = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$record) {
            return ['success' => true, 'status' => 'not_found'];
        }

        $now = new DateTime('now', new DateTimeZone('UTC'));
        $expiredByTime = false;
        if (!empty($record['expires_at'])) {
            $expiredByTime = (new DateTime($record['expires_at'], new DateTimeZone('UTC'))) <= $now;
        }
        $expiredByViews = ((int)$record['remaining_views']) <= 0;
        $status = ($expiredByTime || $expiredByViews) ? 'expired' : 'active';

        if ($this->config['privacy_mode'] && $status !== 'active') {
            return ['success' => true, 'status' => 'not_found'];
        }

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

    private function generateToken(): string
    {
        $length = $this->config['token_length'];
        $entropy = random_bytes($length) . 
                   hash('sha256', microtime(true) . getmypid() . uniqid('', true), true) .
                   random_bytes($length);
        
        $finalHash = hash('sha256', $entropy, true);
        return bin2hex(substr($finalHash, 0, $length));
    }

    private function generateEncryptionKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    private function wrapKey(string $base64Key, string $wrappingKey): string
    {
        $keyMaterial = hash('sha256', $wrappingKey, true);
        $iv = random_bytes(12);
        $tag = '';
        $cipher = openssl_encrypt($base64Key, 'aes-256-gcm', $keyMaterial, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
        if ($cipher === false || $tag === '') {
            throw new Exception('Key wrapping failed');
        }
        return 'wk1:' . base64_encode($iv . $tag . $cipher);
    }

    private function unwrapKey(string $storedKey, string $wrappingKey): string
    {
        if (!str_starts_with($storedKey, 'wk1:')) {
            return $storedKey;
        }
        $payload = base64_decode(substr($storedKey, 4), true);
        if ($payload === false || strlen($payload) < 28) {
            throw new Exception('Invalid wrapped key data');
        }
        $iv = substr($payload, 0, 12);
        $tag = substr($payload, 12, 16);
        $cipher = substr($payload, 28);
        $keyMaterial = hash('sha256', $wrappingKey, true);
        $plain = openssl_decrypt($cipher, 'aes-256-gcm', $keyMaterial, OPENSSL_RAW_DATA, $iv, $tag, '');
        if ($plain === false) {
            throw new Exception('Key unwrapping failed');
        }
        return $plain;
    }

    private function encryptPayload(string $data, string $base64Key): string
    {
        $method = $this->config['encryption_method'];
        $keyBytes = base64_decode($base64Key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        $useV2 = $this->encryptionVersion === self::FORMAT_V2 && stripos($method, 'gcm') !== false;
        if ($useV2) {
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($data, $method, $keyBytes, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($cipher === false || $tag === '') {
                throw new Exception('Encryption failed');
            }
            return 'v2:' . base64_encode($iv . $tag . $cipher);
        }

        // v1 legacy with HMAC (always uses AES-256-CBC)
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'AES-256-CBC', $keyBytes, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            throw new Exception('Encryption failed');
        }
        $payload = $iv . $cipher;
        $macKey = hash('sha256', $keyBytes . 'mac', true);
        $hmac = hash_hmac('sha256', $payload, $macKey, true);
        return 'v1:' . base64_encode($payload . $hmac);
    }

    private function decryptPayload(string $payload, string $base64Key): string
    {
        $method = $this->config['encryption_method'];
        $keyBytes = base64_decode($base64Key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        if (str_starts_with($payload, 'v2:')) {
            $raw = base64_decode(substr($payload, 3), true);
            if ($raw === false || strlen($raw) < 28) {
                throw new Exception('Invalid encrypted data');
            }
            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $cipher = substr($raw, 28);
            $plain = openssl_decrypt($cipher, $method, $keyBytes, OPENSSL_RAW_DATA, $iv, $tag, '');
            if ($plain === false) {
                throw new Exception('Decryption failed');
            }
            return $plain;
        }

        if (!str_starts_with($payload, 'v1:')) {
            throw new Exception('Unsupported encrypted format');
        }
        // v1 always uses AES-256-CBC
        $raw = base64_decode(substr($payload, 3), true);
        if ($raw === false || strlen($raw) < 48) {
            throw new Exception('Invalid encrypted data');
        }
        $iv = substr($raw, 0, 16);
        $cipher = substr($raw, 16, -32);
        $hmac = substr($raw, -32);
        $macKey = hash('sha256', $keyBytes . 'mac', true);
        $calcHmac = hash_hmac('sha256', $iv . $cipher, $macKey, true);
        if (!hash_equals($hmac, $calcHmac)) {
            throw new Exception('Decryption failed');
        }
        $plain = openssl_decrypt($cipher, 'AES-256-CBC', $keyBytes, OPENSSL_RAW_DATA, $iv);
        if ($plain === false) {
            throw new Exception('Decryption failed');
        }
        return $plain;
    }

    private function encryptWithPassword(string $data, string $key, string $password): string
    {
        $salt = random_bytes(16);
        $iterations = $this->config['pbkdf2_iterations'];
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $finalKey = base64_encode($combinedKey);
        
        return $this->encryptPayloadWithKey($data, $finalKey, $salt);
    }

    private function encryptPayloadWithKey(string $data, string $base64Key, ?string $salt = null): string
    {
        $method = $this->config['encryption_method'];
        $keyBytes = base64_decode($base64Key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }
        $useV2 = $this->encryptionVersion === self::FORMAT_V2 && stripos($method, 'gcm') !== false;
        if ($useV2) {
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($data, $method, $keyBytes, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($cipher === false || $tag === '') {
                throw new Exception('Encryption with password failed');
            }
            $payload = ($salt ?? '') . $iv . $tag . $cipher;
            return 'v2:' . base64_encode($payload);
        }
        // v1 legacy with HMAC (always uses AES-256-CBC)
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($data, 'AES-256-CBC', $keyBytes, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            throw new Exception('Encryption with password failed');
        }
        $payload = ($salt ?? '') . $iv . $cipher;
        $macKey = hash('sha256', $keyBytes . 'mac', true);
        $hmac = hash_hmac('sha256', $payload, $macKey, true);
        return 'v1:' . base64_encode($payload . $hmac);
    }

    private function decryptWithPassword(string $encryptedData, string $key, string $password): string
    {
        $method = $this->config['encryption_method'];
        if (str_starts_with($encryptedData, 'v2:')) {
            $raw = base64_decode(substr($encryptedData, 3), true);
            if ($raw === false || strlen($raw) < 44) {
                throw new Exception('Invalid encrypted data');
            }
            $salt = substr($raw, 0, 16);
            $iv = substr($raw, 16, 12);
            $tag = substr($raw, 28, 16);
            $cipher = substr($raw, 44);
            $iterations = $this->config['pbkdf2_iterations'];
            $passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
            $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
            $plain = openssl_decrypt($cipher, $method, $combinedKey, OPENSSL_RAW_DATA, $iv, $tag, '');
            if ($plain === false) {
                throw new Exception('Decryption with password failed');
            }
            return $plain;
        }

        if (!str_starts_with($encryptedData, 'v1:')) {
            throw new Exception('Invalid encrypted data');
        }
        // v1 always uses AES-256-CBC
        $data = base64_decode(substr($encryptedData, 3), true);
        if ($data === false || strlen($data) < 64) {
            throw new Exception('Invalid encrypted data');
        }
        $salt = substr($data, 0, 16);
        $iv = substr($data, 16, 16);
        $encrypted = substr($data, 32, -32);
        $hmac = substr($data, -32);
        $iterations = $this->config['pbkdf2_iterations'];
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $iterations, 32, true);
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $macKey = hash('sha256', $combinedKey . 'mac', true);
        $calcHmac = hash_hmac('sha256', $salt . $iv . $encrypted, $macKey, true);
        if (!hash_equals($hmac, $calcHmac)) {
            throw new Exception('Decryption with password failed');
        }
        $decrypted = openssl_decrypt($encrypted, 'AES-256-CBC', $combinedKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new Exception('Decryption with password failed');
        }
        return $decrypted;
    }

    // ==================== DATABASE METHODS ====================

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
            if ($this->config['secure_delete']) {
                $this->db->exec('PRAGMA journal_mode = DELETE');
                $this->db->exec('PRAGMA secure_delete = ON');
                $this->db->exec('PRAGMA synchronous = FULL');
            } else {
                $this->db->exec('PRAGMA journal_mode = WAL');
                $this->db->exec('PRAGMA synchronous = FULL');
            }

            $this->createTables();
        } catch (PDOException $e) {
            throw new Exception('Database connection failed: ' . $e->getMessage());
        }
    }

    private function createTables(): void
    {
        $sql = "
            CREATE TABLE IF NOT EXISTS encrypted_content (
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
            )
        ";
        $this->db->exec($sql);
        
        $this->db->exec("CREATE INDEX IF NOT EXISTS idx_created_at ON encrypted_content(created_at)");
        $this->db->exec("CREATE INDEX IF NOT EXISTS idx_expires_at ON encrypted_content(expires_at)");
    }

    private function validateTokenFormat(string $token): bool
    {
        return is_string($token) && strlen($token) === 64 && preg_match('/^[a-f0-9]{64}$/i', $token);
    }

    private function tokenExists(string $token): bool
    {
        $stmt = $this->db->prepare("SELECT 1 FROM encrypted_content WHERE token = ?");
        $stmt->execute([$token]);
        return $stmt->fetch() !== false;
    }

    private function store(string $token, string $encryptedData, string $encryptionKey, bool $hasPassword, int $maxViews, bool $isMarkdown, bool $isHtml, ?string $expiresAt): void
    {
        $sql = "INSERT INTO encrypted_content (token, encrypted_data, encryption_key, has_password, is_markdown, is_html, max_views, remaining_views, expires_at) 
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)";
        $stmt = $this->db->prepare($sql);
        $stmt->execute([$token, $encryptedData, $encryptionKey, $hasPassword ? 1 : 0, $isMarkdown ? 1 : 0, $isHtml ? 1 : 0, $maxViews, $maxViews, $expiresAt]);
    }

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

    private function decrementViews(string $token): int
    {
        $this->db->beginTransaction();
        try {
            $stmt = $this->db->prepare("UPDATE encrypted_content SET remaining_views = remaining_views - 1 WHERE token = ? AND remaining_views > 0 RETURNING remaining_views");
            $stmt->execute([$token]);
            $row = $stmt->fetch();
            $remainingViews = $row ? (int)$row['remaining_views'] : -1;
            // Close cursor to release statement before commit
            $stmt->closeCursor();
            $stmt = null;
            
            if ($remainingViews < 0) {
                $this->db->rollBack();
                return 0;
            }
            $this->db->commit();
            return max(0, $remainingViews);
        } catch (PDOException $e) {
            $this->db->rollBack();
            throw $e;
        }
    }

    private function secureDelete(string $token): bool
    {
        try {
            $randomData = base64_encode(random_bytes(1024));
            $randomKey = base64_encode(random_bytes(64));
            $stmt = $this->db->prepare("UPDATE encrypted_content SET encrypted_data = ?, encryption_key = ? WHERE token = ?");
            $stmt->execute([$randomData, $randomKey, $token]);
            $stmt = $this->db->prepare("DELETE FROM encrypted_content WHERE token = ?");
            $stmt->execute([$token]);

            if ($this->config['secure_delete']) {
                $this->db->exec('VACUUM');
            }

            return true;
        } catch (PDOException $e) {
            return false;
        }
    }

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
            $stmt = $this->db->prepare("DELETE FROM encrypted_content 
                    WHERE expires_at IS NULL 
                    AND remaining_views = max_views 
                    AND created_at < datetime('now', '-' || ? || ' days')");
            $stmt->execute([$days]);
            $deleted = $stmt->rowCount();
            $this->db->exec("DELETE FROM encrypted_content WHERE expires_at IS NOT NULL AND expires_at < datetime('now')");
            @touch($marker, $now);
            if ($deleted > 0 && !$this->config['secure_delete']) {
                $this->db->exec('VACUUM');
            }
        } catch (PDOException $e) {
            // Silently fail cleanup
        }
    }

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
