<?php
/**
 * CryptNote PHP Library - Basic Usage Examples
 * 
 * This file demonstrates the basic functionality of the CryptNote library.
 */

require_once __DIR__ . '/../src/CryptNote.php';

use CryptNote\CryptNote;

echo "=== CryptNote PHP Library - Basic Examples ===\n\n";

// Initialize CryptNote
$cryptnote = new CryptNote([
    'db_path' => __DIR__ . '/data/example.db',
    'encryption_method' => 'AES-256-GCM',
    'encryption_version' => 'v2',
    'password_min_length' => 12,
]);

// ============================================
// Example 1: Simple encrypted note
// ============================================
echo "1. Creating a simple encrypted note...\n";

$result = $cryptnote->create('This is my secret message!');

echo "   Token: " . $result['token'] . "\n";
echo "   Max views: " . $result['max_views'] . "\n";
echo "   Has password: " . ($result['has_password'] ? 'Yes' : 'No') . "\n\n";

// View the note
echo "   Viewing the note...\n";
$note = $cryptnote->view($result['token']);
echo "   Content: " . $note['content'] . "\n";
echo "   Remaining views: " . $note['remaining_views'] . "\n";
echo "   Destroyed: " . ($note['destroyed'] ? 'Yes' : 'No') . "\n\n";

// ============================================
// Example 2: Note with multiple views
// ============================================
echo "2. Creating a note with 3 views...\n";

$result = $cryptnote->create('This message can be viewed 3 times', [
    'max_views' => 3,
]);

echo "   Token: " . $result['token'] . "\n";

for ($i = 1; $i <= 3; $i++) {
    $note = $cryptnote->view($result['token']);
    echo "   View $i - Remaining: " . $note['remaining_views'] . ", Destroyed: " . ($note['destroyed'] ? 'Yes' : 'No') . "\n";
}
echo "\n";

// ============================================
// Example 3: Password-protected note
// ============================================
echo "3. Creating a password-protected note...\n";

$result = $cryptnote->create('This is a password-protected secret', [
    'password' => 'mySecretPassword123',
    'max_views' => 2,
]);

echo "   Token: " . $result['token'] . "\n";
echo "   Has password: " . ($result['has_password'] ? 'Yes' : 'No') . "\n";

// Try viewing without password
echo "   Trying to view without password...\n";
try {
    $cryptnote->view($result['token']);
} catch (Exception $e) {
    echo "   Error: " . $e->getMessage() . "\n";
}

// View with correct password
echo "   Viewing with correct password...\n";
$note = $cryptnote->view($result['token'], 'mySecretPassword123');
echo "   Content: " . $note['content'] . "\n\n";

// ============================================
// Example 3b: Password policy enforcement (min length)
// ============================================

echo "3b. Password policy enforcement...\n";

try {
    $cryptnote->create('Short password should fail', [
        'password' => 'short',
    ]);
} catch (Exception $e) {
    echo "   Expected error: " . $e->getMessage() . "\n\n";
}

// ============================================
// Example 4: Note with time expiration
// ============================================
echo "4. Creating a note that expires in 60 minutes...\n";

$result = $cryptnote->create('This message will expire soon', [
    'max_views' => 10,
    'expire_minutes' => 60,
]);

echo "   Token: " . $result['token'] . "\n";
echo "   Expires at: " . $result['expires_at'] . " UTC\n\n";

// ============================================
// Example 5: Check note status
// ============================================
echo "5. Checking note status...\n";

$result = $cryptnote->create('Status check example', [
    'max_views' => 5,
]);

$status = $cryptnote->status($result['token']);
echo "   Status: " . $status['status'] . "\n";
echo "   Remaining views: " . $status['remaining_views'] . "/" . $status['max_views'] . "\n";
echo "   Requires password: " . ($status['requires_password'] ? 'Yes' : 'No') . "\n\n";

// ============================================
// Example 6: Markdown content
// ============================================
echo "6. Creating a Markdown note...\n";

$markdownContent = "# Hello World\n\nThis is **bold** and this is *italic*.\n\n- Item 1\n- Item 2";

$result = $cryptnote->create($markdownContent, [
    'is_markdown' => true,
    'max_views' => 1,
]);

$note = $cryptnote->view($result['token']);
echo "   Is Markdown: " . ($note['is_markdown'] ? 'Yes' : 'No') . "\n";
echo "   Content:\n" . $note['content'] . "\n\n";

// ============================================
// Example 7: Get statistics
// ============================================
echo "7. Database statistics...\n";

$stats = $cryptnote->getStats();
echo "   Total notes: " . $stats['total_notes'] . "\n";
echo "   Unviewed notes: " . $stats['unviewed_notes'] . "\n";
echo "   Password protected: " . $stats['password_protected'] . "\n";
echo "   With expiration: " . $stats['with_expiration'] . "\n\n";

echo "=== Examples completed! ===\n";
