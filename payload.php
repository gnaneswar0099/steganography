<?php
declare(strict_types=1);

/*
|--------------------------------------------------------------------------
| HEADER FORMAT (33 bytes) — No Magic Signature
|--------------------------------------------------------------------------
| Security: No identifiable magic bytes ("STEG") or version markers.
| Detection relies solely on AES-256-GCM authentication tag verification.
| If decryption fails → no message exists. No steganalysis fingerprint.
|
| Offset  Size   Field
| 0       1      LSB Mode (1 or 2)
| 1       16     Salt (PBKDF2)
| 17      12     IV (AES-GCM nonce)
| 29      4      Ciphertext Length (32-bit big-endian)
| Total:  33 bytes
*/

// Shared constants — defined here with a guard so lsb.php (included after)
// can safely skip re-defining them.
if (!defined('STEGO_HEADER_BYTES')) {
    define('STEGO_HEADER_BYTES', 33);
}
if (!defined('STEGO_HEADER_BITS')) {
    define('STEGO_HEADER_BITS', STEGO_HEADER_BYTES * 8);
}

function build_payload(
    int $lsb,
    string $salt,
    string $iv,
    string $ciphertext,
    string $tag
): string {
    return
        chr($lsb) .
        $salt .
        $iv .
        pack('N', strlen($ciphertext)) .
        $ciphertext .
        $tag;
}

function parse_header(string $data): array
{
    if (strlen($data) < STEGO_HEADER_BYTES) {
        throw new RuntimeException('Decryption failed — invalid data or wrong password.');
    }

    return [
        'lsb' => ord($data[0]),
        'salt' => substr($data, 1, 16),
        'iv' => substr($data, 17, 12),
        'len' => unpack('N', substr($data, 29, 4))[1],
        'offset' => STEGO_HEADER_BYTES
    ];
}
