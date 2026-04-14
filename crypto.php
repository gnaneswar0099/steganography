<?php
declare(strict_types=1);

/**
 * Derive master key using PBKDF2
 */
function derive_master_key(string $password, string $salt): string
{
    return hash_pbkdf2(
        'sha256',
        $password,
        $salt,
        100000,     // iterations
        64,         // 64 bytes output
        true        // raw binary
    );
}

/**
 * AES-256-GCM encryption
 */
function aes_encrypt(string $plaintext, string $key, string $iv): array
{
    $tag = '';
    $ciphertext = openssl_encrypt(
        $plaintext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16
    );

    if ($ciphertext === false) {
        throw new RuntimeException('Encryption failed');
    }

    return [$ciphertext, $tag];
}

/**
 * AES-256-GCM decryption
 */
function aes_decrypt(string $ciphertext, string $key, string $iv, string $tag): string
{
    $plaintext = openssl_decrypt(
        $ciphertext,
        'aes-256-gcm',
        $key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag
    );

    if ($plaintext === false) {
        throw new RuntimeException('Invalid password or corrupted image'); // Simplified error for security
    }

    return $plaintext;
}
