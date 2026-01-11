<?php
/**
 * CryptNote PHP Library - Unit Tests
 * 
 * Run with: ./vendor/bin/phpunit tests/
 */

namespace CryptNote\Tests;

use PHPUnit\Framework\TestCase;
use CryptNote\CryptNote;
use CryptNote\CryptNoteStandalone;
use Exception;

class CryptNoteTest extends TestCase
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
        if (file_exists($this->testDbPath)) {
            unlink($this->testDbPath);
        }
        if (file_exists($this->testDbPath . '-wal')) {
            unlink($this->testDbPath . '-wal');
        }
        if (file_exists($this->testDbPath . '-shm')) {
            unlink($this->testDbPath . '-shm');
        }
    }

    // ==================== CREATE TESTS ====================

    public function testCreateSimpleNote(): void
    {
        $result = $this->cryptnote->create('Test message');

        $this->assertTrue($result['success']);
        $this->assertNotEmpty($result['token']);
        $this->assertEquals(64, strlen($result['token']));
        $this->assertFalse($result['has_password']);
        $this->assertEquals(1, $result['max_views']);
    }

    public function testCreateWithMaxViews(): void
    {
        $result = $this->cryptnote->create('Test message', ['max_views' => 5]);

        $this->assertEquals(5, $result['max_views']);
    }

    public function testCreateWithPassword(): void
    {
        $result = $this->cryptnote->create('Test message', ['password' => 'secretpassword123']);

        $this->assertTrue($result['has_password']);
    }

    public function testCreateWithExpiration(): void
    {
        $result = $this->cryptnote->create('Test message', ['expire_minutes' => 60]);

        $this->assertNotNull($result['expires_at']);
    }

    public function testCreateWithMarkdown(): void
    {
        $result = $this->cryptnote->create('# Hello', ['is_markdown' => true]);

        $this->assertTrue($result['is_markdown']);
    }

    public function testCreateEmptyContentThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Content cannot be empty');

        $this->cryptnote->create('');
    }

    public function testCreateShortPasswordThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Password must be at least 12 characters');

        $this->cryptnote->create('Test', ['password' => 'short12345']);
    }

    // ==================== VIEW TESTS ====================

    public function testViewSimpleNote(): void
    {
        $created = $this->cryptnote->create('Secret message');
        $viewed = $this->cryptnote->view($created['token']);

        $this->assertTrue($viewed['success']);
        $this->assertEquals('Secret message', $viewed['content']);
        $this->assertEquals(0, $viewed['remaining_views']);
        $this->assertTrue($viewed['destroyed']);
    }

    public function testViewWithMultipleViews(): void
    {
        $created = $this->cryptnote->create('Test', ['max_views' => 3]);

        $view1 = $this->cryptnote->view($created['token']);
        $this->assertEquals(2, $view1['remaining_views']);
        $this->assertFalse($view1['destroyed']);

        $view2 = $this->cryptnote->view($created['token']);
        $this->assertEquals(1, $view2['remaining_views']);

        $view3 = $this->cryptnote->view($created['token']);
        $this->assertEquals(0, $view3['remaining_views']);
        $this->assertTrue($view3['destroyed']);
    }

    public function testViewWithPassword(): void
    {
        $created = $this->cryptnote->create('Secret', ['password' => 'secretpassword123', 'max_views' => 2]);

        $viewed = $this->cryptnote->view($created['token'], 'secretpassword123');
        $this->assertEquals('Secret', $viewed['content']);
    }

    public function testViewWithWrongPasswordThrows(): void
    {
        $created = $this->cryptnote->create('Secret', ['password' => 'correctpassword1', 'max_views' => 2]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Incorrect password');

        $this->cryptnote->view($created['token'], 'wrongpassword12');
    }

    public function testViewWithoutRequiredPasswordThrows(): void
    {
        $created = $this->cryptnote->create('Secret', ['password' => 'secretpassword123', 'max_views' => 2]);

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Password required');

        $this->cryptnote->view($created['token']);
    }

    public function testViewDestroyedNoteThrows(): void
    {
        $created = $this->cryptnote->create('Test');
        $this->cryptnote->view($created['token']); // First view destroys it

        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Note not found or expired');

        $this->cryptnote->view($created['token']);
    }

    public function testViewInvalidTokenThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid token format');

        $this->cryptnote->view('invalid-token');
    }

    // ==================== STATUS TESTS ====================

    public function testStatusActive(): void
    {
        $created = $this->cryptnote->create('Test', ['max_views' => 3]);
        $status = $this->cryptnote->status($created['token']);

        $this->assertTrue($status['success']);
        $this->assertEquals('active', $status['status']);
        $this->assertEquals(3, $status['remaining_views']);
    }

    public function testStatusNotFound(): void
    {
        $status = $this->cryptnote->status(str_repeat('a', 64));

        $this->assertEquals('not_found', $status['status']);
    }

    public function testStatusInvalidToken(): void
    {
        $status = $this->cryptnote->status('invalid');

        $this->assertEquals('invalid_token', $status['status']);
    }

    // ==================== DELETE TESTS ====================

    public function testDelete(): void
    {
        $created = $this->cryptnote->create('Test', ['max_views' => 5]);
        
        $deleted = $this->cryptnote->delete($created['token']);
        $this->assertTrue($deleted);

        $status = $this->cryptnote->status($created['token']);
        $this->assertEquals('not_found', $status['status']);
    }

    // ==================== STATS TESTS ====================

    public function testGetStats(): void
    {
        $this->cryptnote->create('Test 1');
        $this->cryptnote->create('Test 2', ['password' => 'secretpassword123']);
        $this->cryptnote->create('Test 3', ['expire_minutes' => 60]);

        $stats = $this->cryptnote->getStats();

        $this->assertEquals(3, $stats['total_notes']);
        $this->assertEquals(3, $stats['unviewed_notes']);
        $this->assertEquals(1, $stats['password_protected']);
        $this->assertEquals(1, $stats['with_expiration']);
    }

    public function testCreateWithUnicodeContent(): void
    {
        $content = '你好世界 🔐 Привет мир مرحبا بالعالم';
        $created = $this->cryptnote->create($content, ['max_views' => 2]);
        $viewed = $this->cryptnote->view($created['token']);

        $this->assertEquals($content, $viewed['content']);
    }

    public function testCreateWithHtml(): void
    {
        $result = $this->cryptnote->create('<p>Hello</p>', ['is_html' => true]);

        $this->assertTrue($result['is_html']);
        $this->assertFalse($result['is_markdown']);
    }

    public function testHtmlOverridesMarkdown(): void
    {
        $result = $this->cryptnote->create('Test', ['is_html' => true, 'is_markdown' => true]);

        $this->assertTrue($result['is_html']);
        $this->assertFalse($result['is_markdown']);
    }

    public function testMaxViewsClampedToRange(): void
    {
        $result1 = $this->cryptnote->create('Test', ['max_views' => 0]);
        $this->assertEquals(1, $result1['max_views']);

        $result2 = $this->cryptnote->create('Test', ['max_views' => 200]);
        $this->assertEquals(100, $result2['max_views']);
    }

    public function testExpireMinutesClampedToRange(): void
    {
        $result = $this->cryptnote->create('Test', ['expire_minutes' => 20000]);
        
        // Should be clamped to 10080 (7 days)
        $this->assertNotNull($result['expires_at']);
    }

    public function testContentExceedsMaxLengthThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Content exceeds maximum length');

        $longContent = str_repeat('A', 60000);
        $this->cryptnote->create($longContent);
    }

    public function testPasswordTooLongThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Password cannot exceed 100 characters');

        $this->cryptnote->create('Test', ['password' => str_repeat('a', 101)]);
    }
}

class CryptNoteStandaloneTest extends TestCase
{
    private CryptNoteStandalone $crypto;

    protected function setUp(): void
    {
        $this->crypto = new CryptNoteStandalone();
    }

    public function testGenerateToken(): void
    {
        $token = $this->crypto->generateToken();

        $this->assertEquals(64, strlen($token));
        $this->assertMatchesRegularExpression('/^[a-f0-9]{64}$/', $token);
    }

    public function testGenerateKey(): void
    {
        $key = $this->crypto->generateKey();

        $this->assertNotEmpty($key);
        $decoded = base64_decode($key);
        $this->assertEquals(32, strlen($decoded));
    }

    public function testEncryptDecrypt(): void
    {
        $key = $this->crypto->generateKey();
        $message = 'Hello, World!';

        $encrypted = $this->crypto->encrypt($message, $key);
        $decrypted = $this->crypto->decrypt($encrypted, $key);

        $this->assertEquals($message, $decrypted);
        $this->assertNotEquals($message, $encrypted);
    }

    public function testEncryptDecryptWithPassword(): void
    {
        $key = $this->crypto->generateKey();
        $password = 'myPassword123';
        $message = 'Secret message';

        $encrypted = $this->crypto->encryptWithPassword($message, $key, $password);
        $decrypted = $this->crypto->decryptWithPassword($encrypted, $key, $password);

        $this->assertEquals($message, $decrypted);
    }

    public function testDecryptWithWrongPasswordThrows(): void
    {
        $key = $this->crypto->generateKey();
        $encrypted = $this->crypto->encryptWithPassword('Secret', $key, 'correct');

        $this->expectException(Exception::class);

        $this->crypto->decryptWithPassword($encrypted, $key, 'wrong');
    }

    public function testValidateToken(): void
    {
        $validToken = str_repeat('a', 64);
        $invalidToken = 'invalid';

        $this->assertTrue($this->crypto->validateToken($validToken));
        $this->assertFalse($this->crypto->validateToken($invalidToken));
    }

    public function testSecureCompare(): void
    {
        $this->assertTrue($this->crypto->secureCompare('test', 'test'));
        $this->assertFalse($this->crypto->secureCompare('test', 'other'));
    }

    public function testGeneratePassword(): void
    {
        $password = $this->crypto->generatePassword(16);

        $this->assertEquals(16, strlen($password));
    }

    public function testEncryptDecryptUnicode(): void
    {
        $key = $this->crypto->generateKey();
        $message = '你好世界 🔐 Привет мир مرحبا بالعالم';

        $encrypted = $this->crypto->encrypt($message, $key);
        $decrypted = $this->crypto->decrypt($encrypted, $key);

        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptDecryptEmptyString(): void
    {
        $key = $this->crypto->generateKey();
        $message = '';

        $encrypted = $this->crypto->encrypt($message, $key);
        $decrypted = $this->crypto->decrypt($encrypted, $key);

        $this->assertEquals($message, $decrypted);
    }

    public function testEncryptDecryptLargeContent(): void
    {
        $key = $this->crypto->generateKey();
        $message = str_repeat('A', 100000); // 100KB

        $encrypted = $this->crypto->encrypt($message, $key);
        $decrypted = $this->crypto->decrypt($encrypted, $key);

        $this->assertEquals($message, $decrypted);
    }

    public function testInvalidEncryptionMethodThrows(): void
    {
        $this->expectException(Exception::class);
        $this->expectExceptionMessage('Invalid encryption method');

        new CryptNoteStandalone(['encryption_method' => 'INVALID-METHOD']);
    }
}
