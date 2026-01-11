<?php
/**
 * CryptNote Standalone - Encryption utilities without database
 * 
 * Use this class when you want to handle storage yourself.
 * Provides only encryption/decryption functionality.
 * 
 * @package CryptNote
 * @version 1.0.0
 * @license MIT
 */

namespace CryptNote;

use Exception;

class CryptNoteStandalone
{
    private string $encryptionMethod;
    private int $pbkdf2Iterations;

    /**
     * Initialize standalone encryption utilities.
     *
     * @param array $config Configuration options:
     *   - encryption_method: OpenSSL cipher method (default: AES-256-CBC)
     *   - pbkdf2_iterations: PBKDF2 iterations for password derivation (default: 10000)
     */
    public function __construct(array $config = [])
    {
        $this->encryptionMethod = $config['encryption_method'] ?? 'AES-256-CBC';
        $this->pbkdf2Iterations = $config['pbkdf2_iterations'] ?? 100000;

        // Validate encryption method
        $validMethods = openssl_get_cipher_methods();
        if (!in_array($this->encryptionMethod, $validMethods, true)) {
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
     * Encrypt content.
     *
     * @param string $content Content to encrypt
     * @param string $key Base64-encoded encryption key
     * @return string Base64-encoded encrypted data (IV + ciphertext)
     * @throws Exception If encryption fails
     */
    public function encrypt(string $content, string $key): string
    {
        $iv = random_bytes(16);
        
        $encrypted = openssl_encrypt(
            $content, 
            $this->encryptionMethod, 
            base64_decode($key), 
            OPENSSL_RAW_DATA, 
            $iv
        );
        
        if ($encrypted === false) {
            throw new Exception('Encryption failed');
        }
        
        return base64_encode($iv . $encrypted);
    }

    /**
     * Decrypt content.
     *
     * @param string $encryptedData Base64-encoded encrypted data
     * @param string $key Base64-encoded encryption key
     * @return string Decrypted content
     * @throws Exception If decryption fails
     */
    public function decrypt(string $encryptedData, string $key): string
    {
        $data = base64_decode($encryptedData);
        
        if ($data === false || strlen($data) < 16) {
            throw new Exception('Invalid encrypted data');
        }
        
        $iv = substr($data, 0, 16);
        $encrypted = substr($data, 16);
        
        $decrypted = openssl_decrypt(
            $encrypted, 
            $this->encryptionMethod, 
            base64_decode($key), 
            OPENSSL_RAW_DATA, 
            $iv
        );
        
        if ($decrypted === false) {
            throw new Exception('Decryption failed');
        }
        
        return $decrypted;
    }

    /**
     * Encrypt content with password protection.
     *
     * @param string $content Content to encrypt
     * @param string $key Base64-encoded encryption key
     * @param string $password User password
     * @return string Base64-encoded encrypted data (salt + IV + ciphertext)
     * @throws Exception If encryption fails
     */
    public function encryptWithPassword(string $content, string $key, string $password): string
    {
        $salt = random_bytes(16);
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
        
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $finalKey = base64_encode($combinedKey);
        
        $iv = random_bytes(16);
        
        $encrypted = openssl_encrypt(
            $content, 
            $this->encryptionMethod, 
            base64_decode($finalKey), 
            OPENSSL_RAW_DATA, 
            $iv
        );
        
        if ($encrypted === false) {
            throw new Exception('Encryption with password failed');
        }
        
        return base64_encode($salt . $iv . $encrypted);
    }

    /**
     * Decrypt content with password.
     *
     * @param string $encryptedData Base64-encoded encrypted data
     * @param string $key Base64-encoded encryption key
     * @param string $password User password
     * @return string Decrypted content
     * @throws Exception If decryption fails or password is incorrect
     */
    public function decryptWithPassword(string $encryptedData, string $key, string $password): string
    {
        $data = base64_decode($encryptedData);
        
        if ($data === false || strlen($data) < 32) {
            throw new Exception('Invalid encrypted data');
        }
        
        $salt = substr($data, 0, 16);
        $iv = substr($data, 16, 16);
        $encrypted = substr($data, 32);
        
        $passwordKey = hash_pbkdf2('sha256', $password, $salt, $this->pbkdf2Iterations, 32, true);
        
        $combinedKey = hash('sha256', base64_decode($key) . $passwordKey, true);
        $finalKey = base64_encode($combinedKey);
        
        $decrypted = openssl_decrypt(
            $encrypted, 
            $this->encryptionMethod, 
            base64_decode($finalKey), 
            OPENSSL_RAW_DATA, 
            $iv
        );
        
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
