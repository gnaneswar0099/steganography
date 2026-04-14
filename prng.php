<?php
declare(strict_types=1);

/**
 * Deterministic PRNG using SHA-256 chaining
 */
function prng_stream(string $seed, int $length): array
{
    $output = [];
    $counter = 0;

    while (count($output) < $length) {
        $hash = hash('sha256', $seed . pack('N', $counter), true);
        foreach (str_split($hash) as $byte) {
            $output[] = ord($byte);
            if (count($output) >= $length)
                break;
        }
        $counter++;
    }

    return $output;
}

/**
 * Helper to get a random integer in range [0, max] using the PRNG logic.
 * Note: This re-hashes for each call, which is consistent with the stream logic but stateless.
 * Use for single random numbers. For bulk, use prng_stream.
 */
function prng_int(string $seed, int $counter, int $max): int
{
    // Generate 4 bytes for 32-bit int
    $hash = hash('sha256', $seed . pack('N', $counter), true);
    // Take first 4 bytes
    $val = unpack('N', substr($hash, 0, 4))[1];
    // This is a 32-bit unsigned integer (mostly).
    // Modulo max+1.
    // Note: This has modulo bias but for typical usage here it's acceptable or we can accept it for simplicity.
    // To strictly avoid bias, we would retry, but that changes the "counter" sequence logic.
    // Given requirement 11 "Deterministic... same password MUST always generate same PRNG sequence",
    // simple modulo is preferred to avoid complex state management of "retries".
    return $val % ($max + 1);
}
