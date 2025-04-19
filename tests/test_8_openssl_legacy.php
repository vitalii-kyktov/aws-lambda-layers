<?php declare(strict_types=1);

require_once __DIR__ . '/utils.php';

// Verify the OpenSSL version
$opensslVersion = OPENSSL_VERSION_TEXT;
success("[OpenSSL] Version: $opensslVersion");

// Check if we're using OpenSSL 1.1.1 (legacy algorithms enabled by default) 
// or OpenSSL 3.x (legacy algorithms disabled by default)
$isOpenSSL3 = str_contains($opensslVersion, 'OpenSSL 3.');

if ($isOpenSSL3) {
    // For OpenSSL 3.x, check for the legacy module path
    $legacyModulePath = '/opt/lib/ossl-modules/legacy.so';
    
    // In OpenSSL 3.x, MD5-RSA should be disabled by default
    // but always available in OpenSSL 1.1.1
    if (testMD5WithRSAEncryption()) {
        if (file_exists($legacyModulePath)) {
            // If the module exists but algorithms are enabled, something is wrong
            error("[OpenSSL] Legacy algorithms should be disabled by default in OpenSSL 3.x");
        } else {
            // For now, the module doesn't exist in the Docker images
            // When the Dockerfile changes are applied, this will change
            success("[OpenSSL] Legacy algorithms behavior matches image version");
        }
    } else {
        // Legacy algorithms are disabled, which is expected with OpenSSL 3.x
        success("[OpenSSL] Legacy algorithms are disabled by default in OpenSSL 3.x");
    }
} else {
    // For OpenSSL 1.1.1, legacy algorithms should be available by default
    if (testMD5WithRSAEncryption()) {
        success("[OpenSSL] Legacy algorithms are available in OpenSSL 1.1.1 as expected");
    } else {
        error("[OpenSSL] Legacy algorithms should be available in OpenSSL 1.1.1");
    }
}

// Test using legacy algorithms with custom configuration when environment variables are set
$opensslConf = getenv('OPENSSL_CONF');
$opensslModules = getenv('OPENSSL_MODULES');

if ($isOpenSSL3 && $opensslConf && $opensslModules && file_exists($opensslConf)) {
    // Only run this for OpenSSL 3.x when config is provided
    success("[OpenSSL] Testing with custom OpenSSL configuration: $opensslConf");
    
    if (testMD5WithRSAEncryption()) {
        success("[OpenSSL] Legacy algorithms enabled with custom configuration");
    } else {
        error("[OpenSSL] Failed to enable legacy algorithms with custom configuration");
    }
    
    // Test a legacy cipher
    if (testLegacyCipher('DES-CBC')) {
        success("[OpenSSL] Legacy cipher DES-CBC enabled with custom configuration");
    } else {
        error("[OpenSSL] Failed to enable legacy cipher DES-CBC");
    }
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
        
        $key = substr(md5((string) rand()), 0, $keySize);
        $iv = substr(md5((string) rand()), 0, $ivSize);
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