<?php
/**
 * CryptNote PHP Library - Standalone Encryption Examples
 * 
 * This file demonstrates using the standalone encryption utilities
 * without the built-in database storage.
 */

require_once __DIR__ . '/../src/CryptNoteStandalone.php';

use CryptNote\CryptNoteStandalone;

echo "=== CryptNote Standalone Encryption Examples ===\n\n";

$crypto = new CryptNoteStandalone();

// ============================================
// Example 1: Basic encryption/decryption
// ============================================
echo "1. Basic encryption and decryption...\n";

$key = $crypto->generateKey();
$message = "Hello, this is a secret message!";

echo "   Original: $message\n";
echo "   Key: $key\n";

$encrypted = $crypto->encrypt($message, $key);
echo "   Encrypted: " . substr($encrypted, 0, 50) . "...\n";

$decrypted = $crypto->decrypt($encrypted, $key);
echo "   Decrypted: $decrypted\n\n";

// ============================================
// Example 2: Password-protected encryption
// ============================================
echo "2. Password-protected encryption...\n";

$key = $crypto->generateKey();
$password = "mySecretPassword123";
$message = "This message requires a password to decrypt";

echo "   Original: $message\n";
echo "   Password: $password\n";

$encrypted = $crypto->encryptWithPassword($message, $key, $password);
echo "   Encrypted: " . substr($encrypted, 0, 50) . "...\n";

$decrypted = $crypto->decryptWithPassword($encrypted, $key, $password);
echo "   Decrypted: $decrypted\n\n";

// ============================================
// Example 3: Token generation and validation
// ============================================
echo "3. Token generation and validation...\n";

$token = $crypto->generateToken();
echo "   Generated token: $token\n";
echo "   Token length: " . strlen($token) . " characters\n";
echo "   Is valid: " . ($crypto->validateToken($token) ? 'Yes' : 'No') . "\n";

$invalidToken = "not-a-valid-token";
echo "   Invalid token '$invalidToken' is valid: " . ($crypto->validateToken($invalidToken) ? 'Yes' : 'No') . "\n\n";

// ============================================
// Example 4: Password generation
// ============================================
echo "4. Password generation...\n";

$password1 = $crypto->generatePassword(16, true);
echo "   With special chars (16): $password1\n";

$password2 = $crypto->generatePassword(12, false);
echo "   Without special chars (12): $password2\n";

$password3 = $crypto->generatePassword(24, true);
echo "   Long password (24): $password3\n\n";

// ============================================
// Example 5: Secure comparison
// ============================================
echo "5. Secure string comparison (timing-safe)...\n";

$known = "secret_token_123";
$correct = "secret_token_123";
$wrong = "secret_token_456";

echo "   Comparing '$known' with '$correct': " . ($crypto->secureCompare($known, $correct) ? 'Match' : 'No match') . "\n";
echo "   Comparing '$known' with '$wrong': " . ($crypto->secureCompare($known, $wrong) ? 'Match' : 'No match') . "\n\n";

// ============================================
// Example 6: Custom storage implementation
// ============================================
echo "6. Example: Custom storage implementation...\n";

// This shows how you might use the standalone class with your own storage
class MySecretStorage {
    private CryptNoteStandalone $crypto;
    private array $storage = [];
    
    public function __construct() {
        $this->crypto = new CryptNoteStandalone();
    }
    
    public function store(string $content, ?string $password = null): string {
        $token = $this->crypto->generateToken();
        $key = $this->crypto->generateKey();
        
        if ($password) {
            $encrypted = $this->crypto->encryptWithPassword($content, $key, $password);
        } else {
            $encrypted = $this->crypto->encrypt($content, $key);
        }
        
        $this->storage[$token] = [
            'encrypted' => $encrypted,
            'key' => $key,
            'has_password' => $password !== null,
        ];
        
        return $token;
    }
    
    public function retrieve(string $token, ?string $password = null): ?string {
        if (!isset($this->storage[$token])) {
            return null;
        }
        
        $data = $this->storage[$token];
        
        if ($data['has_password']) {
            return $this->crypto->decryptWithPassword($data['encrypted'], $data['key'], $password);
        }
        
        return $this->crypto->decrypt($data['encrypted'], $data['key']);
    }
}

$storage = new MySecretStorage();

// Store without password
$token1 = $storage->store("My secret data");
echo "   Stored without password, token: " . substr($token1, 0, 16) . "...\n";
echo "   Retrieved: " . $storage->retrieve($token1) . "\n";

// Store with password
$token2 = $storage->store("Password protected data", "pass123");
echo "   Stored with password, token: " . substr($token2, 0, 16) . "...\n";
echo "   Retrieved: " . $storage->retrieve($token2, "pass123") . "\n\n";

echo "=== Standalone examples completed! ===\n";
