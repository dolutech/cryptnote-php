<?php
/**
 * CryptNote Standalone - Encryption utilities without database
 * 
 * Use this class when you want to handle storage yourself.
 * Provides only encryption/decryption functionality.
 * 
 * @package CryptNote
 * @version 0.2.0
 * @license MIT
 */

namespace CryptNote;

use Exception;

class CryptNoteStandalone
{
    private const FORMAT_V1 = 'v1'; // CBC + HMAC
    private const FORMAT_V2 = 'v2'; // GCM (AEAD)

    private string $encryptionMethod;
    private string $encryptionVersion;
    private int $pbkdf2Iterations;

    /**
     * Initialize standalone encryption utilities.
     *
     * @param array $config Configuration options:
     *   - encryption_method: OpenSSL cipher method (default: AES-256-GCM)
     *   - encryption_version: v2 (AEAD) or v1 (legacy CBC+HMAC) (default: v2)
     *   - pbkdf2_iterations: PBKDF2 iterations for password derivation (default: 100000)
     */
    public function __construct(array $config = [])
    {
        $this->encryptionMethod = $config['encryption_method'] ?? 'AES-256-GCM';
        $this->pbkdf2Iterations = $config['pbkdf2_iterations'] ?? 100000;
        $encVersion = $config['encryption_version'] ?? self::FORMAT_V2;
        $this->encryptionVersion = $encVersion === self::FORMAT_V1 ? self::FORMAT_V1 : self::FORMAT_V2;

        // Validate encryption method (case-insensitive comparison)
        $validMethods = openssl_get_cipher_methods();
        $methodValid = false;
        foreach ($validMethods as $method) {
            if (strcasecmp($this->encryptionMethod, $method) === 0) {
                $methodValid = true;
                break;
            }
        }
        if (!$methodValid) {
            throw new Exception('Invalid encryption method: ' . $this->encryptionMethod);
        }
    }

    /**
     * Generate a secure random token.
     *
     * @param int $length Token length in bytes (default: 32, produces 64 hex chars)
     * @return string Hexadecimal token
     */
    public function generateToken(int $length = 32): string
    {
        $entropy = random_bytes($length) . 
                   hash('sha256', microtime(true) . getmypid() . uniqid('', true), true) .
                   random_bytes($length);
        
        $finalHash = hash('sha256', $entropy, true);
        return bin2hex(substr($finalHash, 0, $length));
    }

    /**
     * Generate a random encryption key.
     *
     * @return string Base64-encoded 256-bit key
     */
    public function generateKey(): string
    {
        return base64_encode(random_bytes(32));
    }

    /**
     * Encrypt content using AES-256-GCM (v2) or AES-256-CBC+HMAC (v1).
     *
     * @param string $content Content to encrypt
     * @param string $key Base64-encoded encryption key
     * @return string Versioned encrypted data (v2: or v1: prefix + base64)
     * @throws Exception If encryption fails
     */
    public function encrypt(string $content, string $key): string
    {
        $keyBytes = base64_decode($key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        $useV2 = $this->encryptionVersion === self::FORMAT_V2 && stripos($this->encryptionMethod, 'gcm') !== false;

        if ($useV2) {
            // GCM AEAD encryption
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($content, $this->encryptionMethod, $keyBytes, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($cipher === false || $tag === '') {
                throw new Exception('Encryption failed');
            }
            return 'v2:' . base64_encode($iv . $tag . $cipher);
        }

        // v1 legacy CBC + HMAC (always uses AES-256-CBC)
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($content, 'AES-256-CBC', $keyBytes, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            throw new Exception('Encryption failed');
        }
        $payload = $iv . $cipher;
        $macKey = hash('sha256', $keyBytes . 'mac', true);
        $hmac = hash_hmac('sha256', $payload, $macKey, true);
        return 'v1:' . base64_encode($payload . $hmac);
    }

    /**
     * Decrypt content (auto-detects v2 GCM or v1 CBC+HMAC format).
     *
     * @param string $encryptedData Versioned encrypted data
     * @param string $key Base64-encoded encryption key
     * @return string Decrypted content
     * @throws Exception If decryption fails
     */
    public function decrypt(string $encryptedData, string $key): string
    {
        $keyBytes = base64_decode($key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        if (str_starts_with($encryptedData, 'v2:')) {
            // GCM AEAD decryption
            $raw = base64_decode(substr($encryptedData, 3), true);
            if ($raw === false || strlen($raw) < 28) {
                throw new Exception('Invalid encrypted data');
            }
            $iv = substr($raw, 0, 12);
            $tag = substr($raw, 12, 16);
            $cipher = substr($raw, 28);
            $plain = openssl_decrypt($cipher, $this->encryptionMethod, $keyBytes, OPENSSL_RAW_DATA, $iv, $tag, '');
            if ($plain === false) {
                throw new Exception('Decryption failed');
            }
            return $plain;
        }

        if (str_starts_with($encryptedData, 'v1:')) {
            // v1 CBC + HMAC decryption (uses AES-256-CBC regardless of configured method)
            $raw = base64_decode(substr($encryptedData, 3), true);
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
            // v1 always uses CBC mode
            $plain = openssl_decrypt($cipher, 'AES-256-CBC', $keyBytes, OPENSSL_RAW_DATA, $iv);
            if ($plain === false) {
                throw new Exception('Decryption failed');
            }
            return $plain;
        }

        // Legacy format without version prefix (backward compatibility)
        $data = base64_decode($encryptedData, true);
        if ($data === false || strlen($data) < 16) {
            throw new Exception('Invalid encrypted data');
        }
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        $decrypted = openssl_decrypt($encrypted, $this->encryptionMethod, $keyBytes, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        return $decrypted;
    }

    /**
     * Encrypt content with password protection using AES-256-GCM (v2) or AES-256-CBC+HMAC (v1).
     *
     * @param string $content Content to encrypt
     * @param string $key Base64-encoded encryption key
     * @param string $password User password
     * @return string Versioned encrypted data (v2: or v1: prefix + base64)
     * @throws Exception If encryption fails
     */
    public function encryptWithPassword(string $content, string $key, string $password): string
    {
        $keyBytes = base64_decode($key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        $salt = random_bytes(16);
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
        $combinedKey = hash('sha256', $keyBytes . $passwordKey, true);

        $useV2 = $this->encryptionVersion === self::FORMAT_V2 && stripos($this->encryptionMethod, 'gcm') !== false;

        if ($useV2) {
            // GCM AEAD encryption
            $iv = random_bytes(12);
            $tag = '';
            $cipher = openssl_encrypt($content, $this->encryptionMethod, $combinedKey, OPENSSL_RAW_DATA, $iv, $tag, '', 16);
            if ($cipher === false || $tag === '') {
                throw new Exception('Encryption with password failed');
            }
            return 'v2:' . base64_encode($salt . $iv . $tag . $cipher);
        }

        // v1 legacy CBC + HMAC (always uses AES-256-CBC)
        $iv = random_bytes(16);
        $cipher = openssl_encrypt($content, 'AES-256-CBC', $combinedKey, OPENSSL_RAW_DATA, $iv);
        if ($cipher === false) {
            throw new Exception('Encryption with password failed');
        }
        $payload = $salt . $iv . $cipher;
        $macKey = hash('sha256', $combinedKey . 'mac', true);
        $hmac = hash_hmac('sha256', $payload, $macKey, true);
        return 'v1:' . base64_encode($payload . $hmac);
    }

    /**
     * Decrypt content with password (auto-detects v2 GCM or v1 CBC+HMAC format).
     *
     * @param string $encryptedData Versioned encrypted data
     * @param string $key Base64-encoded encryption key
     * @param string $password User password
     * @return string Decrypted content
     * @throws Exception If decryption fails or password is incorrect
     */
    public function decryptWithPassword(string $encryptedData, string $key, string $password): string
    {
        $keyBytes = base64_decode($key, true);
        if ($keyBytes === false) {
            throw new Exception('Invalid key');
        }

        if (str_starts_with($encryptedData, 'v2:')) {
            // GCM AEAD decryption
            $raw = base64_decode(substr($encryptedData, 3), true);
            if ($raw === false || strlen($raw) < 44) {
                throw new Exception('Invalid encrypted data');
            }
            $salt = substr($raw, 0, 16);
            $iv = substr($raw, 16, 12);
            $tag = substr($raw, 28, 16);
            $cipher = substr($raw, 44);
            $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
            $combinedKey = hash('sha256', $keyBytes . $passwordKey, true);
            $plain = openssl_decrypt($cipher, $this->encryptionMethod, $combinedKey, OPENSSL_RAW_DATA, $iv, $tag, '');
            if ($plain === false) {
                throw new Exception('Decryption failed - incorrect password or corrupted data');
            }
            return $plain;
        }

        if (str_starts_with($encryptedData, 'v1:')) {
            // v1 CBC + HMAC decryption (uses AES-256-CBC regardless of configured method)
            $raw = base64_decode(substr($encryptedData, 3), true);
            if ($raw === false || strlen($raw) < 64) {
                throw new Exception('Invalid encrypted data');
            }
            $salt = substr($raw, 0, 16);
            $iv = substr($raw, 16, 16);
            $cipher = substr($raw, 32, -32);
            $hmac = substr($raw, -32);
            $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
            $combinedKey = hash('sha256', $keyBytes . $passwordKey, true);
            $macKey = hash('sha256', $combinedKey . 'mac', true);
            $calcHmac = hash_hmac('sha256', $salt . $iv . $cipher, $macKey, true);
            if (!hash_equals($hmac, $calcHmac)) {
                throw new Exception('Decryption failed - incorrect password or corrupted data');
            }
            // v1 always uses CBC mode
            $plain = openssl_decrypt($cipher, 'AES-256-CBC', $combinedKey, OPENSSL_RAW_DATA, $iv);
            if ($plain === false) {
                throw new Exception('Decryption failed - incorrect password or corrupted data');
            }
            return $plain;
        }

        // Legacy format without version prefix (backward compatibility)
        $data = base64_decode($encryptedData, true);
        if ($data === false || strlen($data) < 32) {
            throw new Exception('Invalid encrypted data');
        }
        $salt = substr($data, 0, 16);
        $iv = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
        $combinedKey = hash('sha256', $keyBytes . $passwordKey, true);
        $decrypted = openssl_decrypt($encrypted, $this->encryptionMethod, $combinedKey, OPENSSL_RAW_DATA, $iv);
        if ($decrypted === false) {
            throw new Exception('Decryption failed - incorrect password or corrupted data');
        }
        return $decrypted;
    }

    /**
     * Validate token format.
     *
     * @param string $token Token to validate
     * @param int $expectedLength Expected length in hex characters (default: 64)
     * @return bool True if valid
     */
    public function validateToken(string $token, int $expectedLength = 64): bool
    {
        return is_string($token) 
            && strlen($token) === $expectedLength 
            && preg_match('/^[a-f0-9]{' . $expectedLength . '}$/i', $token);
    }

    /**
     * Securely compare two strings (timing-safe).
     *
     * @param string $known Known string
     * @param string $user User-provided string
     * @return bool True if equal
     */
    public function secureCompare(string $known, string $user): bool
    {
        return hash_equals($known, $user);
    }

    /**
     * Generate a secure random password.
     *
     * @param int $length Password length (default: 16)
     * @param bool $includeSpecial Include special characters (default: true)
     * @return string Random password
     */
    public function generatePassword(int $length = 16, bool $includeSpecial = true): string
    {
        $chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
        if ($includeSpecial) {
            $chars .= '!@#$%^&*()_+-=[]{}|;:,.<>?';
        }
        
        $password = '';
        $max = strlen($chars) - 1;
        
        for ($i = 0; $i < $length; $i++) {
            $password .= $chars[random_int(0, $max)];
        }
        
        return $password;
    }
}
