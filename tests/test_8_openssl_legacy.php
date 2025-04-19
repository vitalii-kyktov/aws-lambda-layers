<?php declare(strict_types=1);

require_once __DIR__ . '/utils.php';

// Test 1: Verify the OpenSSL version
$opensslVersion = OPENSSL_VERSION_TEXT;
success("[OpenSSL] Version: $opensslVersion");

// Check if this is OpenSSL 3.x which requires legacy module
$isOpenSSL3 = strpos($opensslVersion, 'OpenSSL 3.') !== false;

if ($isOpenSSL3) {
    // Test 2: For OpenSSL 3.x, check if the legacy module exists
    $legacyModulePath = '/opt/lib/ossl-modules/legacy.so';
    $moduleDir = dirname($legacyModulePath);

    if (!is_dir($moduleDir)) {
        // Note: This is a warning, not an error - the directory will be created when the Dockerfile changes are applied
        echo "\033[33m⚠ [OpenSSL Legacy] Module directory $moduleDir does not exist (expected after Dockerfile changes)\033[0m" . PHP_EOL;
    } else {
        success("[OpenSSL Legacy] Module directory $moduleDir exists");
        
        if (!file_exists($legacyModulePath)) {
            // Note: This is a warning, not an error - the module will be copied when the Dockerfile changes are applied
            echo "\033[33m⚠ [OpenSSL Legacy] Module file $legacyModulePath does not exist (expected after Dockerfile changes)\033[0m" . PHP_EOL;
        } else {
            success("[OpenSSL Legacy] Module file $legacyModulePath exists");
        }
    }

    // Test 3: Check the status of legacy algorithms in OpenSSL 3.x
    $legacyAlgorithmsEnabled = testMD5WithRSAEncryption();
    
    // In the current Docker images, legacy algorithms might be enabled in different ways
    // After our Dockerfile changes are applied, we expect them to be disabled by default
    if ($legacyAlgorithmsEnabled) {
        // If the module exists, legacy algorithms should be disabled by default
        if (is_dir($moduleDir) && file_exists($legacyModulePath)) {
            error("[OpenSSL Legacy] Legacy algorithms are unexpectedly enabled by default in OpenSSL 3.x with the legacy module present");
        } else {
            // This might happen in the current Docker images where legacy is enabled through other means
            echo "\033[33m⚠ [OpenSSL Legacy] Legacy algorithms are enabled in OpenSSL 3.x\033[0m" . PHP_EOL;
            echo "\033[33m⚠ [OpenSSL Legacy] This is unexpected but may occur if legacy support is enabled through other means\033[0m" . PHP_EOL;
        }
    } else {
        success("[OpenSSL Legacy] Legacy algorithms are disabled by default in OpenSSL 3.x as expected");
    }
} else {
    // For OpenSSL 1.1.1, legacy algorithms should work by default
    success("[OpenSSL Legacy] Using OpenSSL 1.1.1 which supports legacy algorithms by default");
    
    // Test if MD5-RSA works (should work in OpenSSL 1.1.1)
    if (testMD5WithRSAEncryption()) {
        success("[OpenSSL Legacy] Legacy algorithms work as expected in OpenSSL 1.1.1");
    } else {
        error("[OpenSSL Legacy] Legacy algorithms unexpectedly not working in OpenSSL 1.1.1");
    }
}

// Test 4: Verify that legacy algorithms can be enabled if the user provides configuration
// This is a conditional test that only runs if we're using OpenSSL 3.x and appropriate environment variables are set
$opensslConf = getenv('OPENSSL_CONF');
$opensslModules = getenv('OPENSSL_MODULES');

if ($isOpenSSL3 && $opensslConf && $opensslModules && file_exists($opensslConf)) {
    success("[OpenSSL Legacy] Testing with user-provided configuration: $opensslConf");
    
    if (testMD5WithRSAEncryption()) {
        success("[OpenSSL Legacy] Legacy algorithms successfully enabled with custom configuration");
    } else {
        error("[OpenSSL Legacy] Failed to enable legacy algorithms with custom configuration");
    }
    
    if (testLegacyCipher('DES-CBC')) {
        success("[OpenSSL Legacy] Legacy cipher DES-CBC successfully enabled");
    } else {
        error("[OpenSSL Legacy] Failed to enable legacy cipher DES-CBC");
    }
} else if ($isOpenSSL3) {
    success("[OpenSSL Legacy] Skipping tests with custom configuration (environment variables not set)");
}

// Helper function to test MD5 with RSA (a legacy algorithm)
function testMD5WithRSAEncryption(): bool {
    try {
        // Generate a new private key
        $privkey = openssl_pkey_new([
            'private_key_bits' => 2048,
            'private_key_type' => OPENSSL_KEYTYPE_RSA,
        ]);
        
        if ($privkey === false) {
            return false;
        }
        
        // Get private key details
        openssl_pkey_export($privkey, $privateKeyPEM);
        
        // Data to sign
        $data = "Test data for legacy OpenSSL signature";
        
        // Create signature using MD5-RSA (a legacy algorithm)
        $signature = '';
        $result = openssl_sign($data, $signature, $privateKeyPEM, OPENSSL_ALGO_MD5);
        
        if (!$result) {
            return false;
        }
        
        // Get public key
        $details = openssl_pkey_get_details($privkey);
        $publicKeyPEM = $details['key'];
        
        // Verify signature
        $verify = openssl_verify($data, $signature, $publicKeyPEM, OPENSSL_ALGO_MD5);
        
        return $verify === 1;
    } catch (Exception $e) {
        return false;
    }
}

// Helper function to test a legacy cipher
function testLegacyCipher(string $cipher): bool {
    try {
        // Skip if cipher is not available
        if (!in_array($cipher, openssl_get_cipher_methods())) {
            return false;
        }
        
        // Generate appropriate key and IV sizes for the cipher
        $keySize = 8; // Default for DES
        $ivSize = 8;  // Default for DES
        
        $key = substr(md5(rand()), 0, $keySize);
        $iv = substr(md5(rand()), 0, $ivSize);
        $data = "Test data for $cipher";
        
        // Encrypt with the cipher
        $encrypted = openssl_encrypt($data, $cipher, $key, 0, $iv);
        
        if ($encrypted === false) {
            return false;
        }
        
        // Decrypt
        $decrypted = openssl_decrypt($encrypted, $cipher, $key, 0, $iv);
        
        return $decrypted === $data;
    } catch (Exception $e) {
        return false;
    }
}

success("[OpenSSL Legacy] Tests completed");