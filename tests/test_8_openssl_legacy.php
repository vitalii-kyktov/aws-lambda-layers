<?php declare(strict_types=1);

require_once __DIR__ . '/utils.php';

// Run twice: without OPENSSL_CONF/OPENSSL_MODULES the legacy provider must be off,
// with them (pointing at /opt/lib/ossl-modules) legacy algorithms must work.
$expectLegacy = getenv('OPENSSL_MODULES') !== false;

if (! file_exists('/opt/lib/ossl-modules/legacy.so')) {
    error('[OpenSSL] /opt/lib/ossl-modules/legacy.so is missing from the layer');
}
success('[OpenSSL] ' . OPENSSL_VERSION_TEXT . ', legacy.so present');

$legacyWorks = md5RsaSignatureWorks() && desCbcWorks();

if ($expectLegacy && ! $legacyWorks) {
    error('[OpenSSL] Legacy provider enabled via OPENSSL_CONF/OPENSSL_MODULES but legacy algorithms fail');
}
if (! $expectLegacy && $legacyWorks) {
    error('[OpenSSL] Legacy algorithms work without the legacy provider being enabled');
}
success($expectLegacy
    ? '[OpenSSL] Legacy algorithms (MD5-RSA, DES-CBC) work with the legacy provider enabled'
    : '[OpenSSL] Legacy algorithms are disabled by default');

function md5RsaSignatureWorks(): bool
{
    $key = openssl_pkey_new(['private_key_bits' => 2048, 'private_key_type' => OPENSSL_KEYTYPE_RSA]);
    if ($key === false) return false;
    $signature = '';
    if (! @openssl_sign('data', $signature, $key, OPENSSL_ALGO_MD5)) return false;
    return @openssl_verify('data', $signature, openssl_pkey_get_details($key)['key'], OPENSSL_ALGO_MD5) === 1;
}

function desCbcWorks(): bool
{
    $encrypted = @openssl_encrypt('data', 'DES-CBC', '12345678', 0, '87654321');
    return $encrypted !== false && @openssl_decrypt($encrypted, 'DES-CBC', '12345678', 0, '87654321') === 'data';
}
