<?php
declare(strict_types=1);

require_once 'prng.php';

/*
|--------------------------------------------------------------------------
| GD-BASED LSB STEGANOGRAPHY ENGINE
|--------------------------------------------------------------------------
| Uses PHP's built-in GD extension (bundled with XAMPP — no Imagick needed).
|
| Fixes vs previous version:
|  - Removed imagefill() that was destroying the cover image pixels
|  - Proper alpha-to-opaque conversion without overwriting pixels
|  - Packed 4-byte values for the shuffle index list
|  - Pixel index: flat = y * width + x
*/

/* =========================
   CONSTANTS
========================= */
if (!defined('STEGO_HEADER_BYTES')) {
    define('STEGO_HEADER_BYTES', 33);
}
if (!defined('STEGO_HEADER_BITS')) {
    define('STEGO_HEADER_BITS', STEGO_HEADER_BYTES * 8);
}

/* =========================
   EXTENSION CHECK
========================= */
if (!extension_loaded('gd')) {
    throw new RuntimeException(
        'GD extension is required. Enable it in php.ini: extension=gd'
    );
}

/* =========================
   BIT UTILITIES
========================= */

function bits_to_bytes(array $bits): string
{
    $bytes = '';
    $count = count($bits);
    for ($i = 0; $i < $count; $i += 8) {
        $byte = 0;
        for ($j = 0; $j < 8; $j++) {
            $byte <<= 1;
            if (($i + $j) < $count) {
                $byte |= $bits[$i + $j];
            }
        }
        $bytes .= chr($byte);
    }
    return $bytes;
}

/* =========================
   IMAGE I/O HELPERS
========================= */

/**
 * Load a PNG or JPEG into a truecolor GD image.
 * Alpha channels are flattened onto a white background.
 * Returns [$img, $width, $height].
 */
function load_image_gd(string $imagePath): array
{
    $info = @getimagesize($imagePath);
    if ($info === false) {
        throw new RuntimeException("Cannot read image: $imagePath");
    }

    $type = $info[2];
    $width = (int) $info[0];
    $height = (int) $info[1];

    if ($type === IMAGETYPE_PNG) {
        $src = @imagecreatefrompng($imagePath);
    } elseif ($type === IMAGETYPE_JPEG) {
        $src = @imagecreatefromjpeg($imagePath);
    } else {
        throw new RuntimeException("Only PNG and JPEG cover images are supported.");
    }

    if ($src === false) {
        throw new RuntimeException("GD failed to decode the image file.");
    }

    // Create a fresh truecolor canvas (white background) and copy image onto it.
    // This flattens any alpha channel without touching the RGB pixel data.
    $img = imagecreatetruecolor($width, $height);
    if ($img === false) {
        imagedestroy($src);
        throw new RuntimeException("GD could not allocate truecolor canvas.");
    }

    // Fill canvas with white (so transparent areas become white)
    imagefill($img, 0, 0, imagecolorallocate($img, 255, 255, 255));

    // Blend source onto white canvas
    imagealphablending($img, true);
    imagecopy($img, $src, 0, 0, 0, 0, $width, $height);
    imagedestroy($src);

    // Lock: no alpha saving on output
    imagesavealpha($img, false);

    return [$img, $width, $height];
}

/**
 * Export a GD image as a PNG binary string.
 */
function gd_to_png($img): string
{
    ob_start();
    $ok = imagepng($img);
    $data = ob_get_clean();

    if ($ok === false || $data === false || $data === '') {
        throw new RuntimeException("GD imagepng() failed to produce output.");
    }

    return (string) $data;
}

/* =========================
   PIXEL HELPERS
========================= */

/** Read [R, G, B] at flat pixel index. */
function get_pixel($img, int $index, int $width): array
{
    $c = imagecolorat($img, $index % $width, intdiv($index, $width));
    if ($c === false) {
        throw new RuntimeException("Image bounds exceeded or pixel read failed.");
    }
    return [($c >> 16) & 0xFF, ($c >> 8) & 0xFF, $c & 0xFF];
}

/** Write [R, G, B] at flat pixel index. */
function set_pixel($img, int $index, int $width, int $r, int $g, int $b): void
{
    imagesetpixel($img, $index % $width, intdiv($index, $width), ($r << 16) | ($g << 8) | $b);
}

/* =========================
   PRNG-SHUFFLE HELPER
========================= */

/**
 * Build the shuffled pixel index list using Fisher-Yates (partial).
 * Uses packed 4-byte values to reduce memory vs PHP array entries.
 *
 * @param int $start        First available pixel index (after header)
 * @param int $total        Total pixel count of image
 * @param int $needed       How many shuffled slots we actually need
 * @param string $prngSeed  32-byte binary seed
 * @return string           Packed indices [0..$needed-1] are selected pixels
 */
function packed_index_get(string $indexes, int $position): int
{
    return unpack('N', substr($indexes, $position * 4, 4))[1];
}

function packed_index_set(string &$indexes, int $position, int $value): void
{
    $offset = $position * 4;
    $packed = pack('N', $value);
    for ($i = 0; $i < 4; $i++) {
        $indexes[$offset + $i] = $packed[$i];
    }
}

function build_shuffle(int $start, int $total, int $needed, string $prngSeed): string
{
    $count = $total - $start;
    $idx = '';
    for ($i = 0; $i < $count; $i++) {
        $idx .= pack('N', $start + $i);
    }

    $prngCounter = 0;
    for ($i = 0; $i < $needed; $i++) {
        $j = $i + prng_int($prngSeed, $prngCounter++, $count - $i - 1);
        $tmp = packed_index_get($idx, $i);
        packed_index_set($idx, $i, packed_index_get($idx, $j));
        packed_index_set($idx, $j, $tmp);
    }

    return $idx;
}

function payload_bit(string $data, int $bitIndex): int
{
    return (ord($data[$bitIndex >> 3]) >> (7 - ($bitIndex & 7))) & 1;
}

/* =========================
   EMBEDDING
========================= */

function embed_lsb(string $imagePath, string $payload, int $lsbMode, string $prngSeed): string
{
    if ($lsbMode !== 1 && $lsbMode !== 2) {
        throw new RuntimeException("Invalid LSB mode: must be 1 or 2.");
    }

    [$img, $width, $height] = load_image_gd($imagePath);
    $totalPixels = $width * $height;

    $headerData = substr($payload, 0, STEGO_HEADER_BYTES);
    $bodyData = substr($payload, STEGO_HEADER_BYTES);
    $headerBitCount = strlen($headerData) * 8;
    $bodyBitCount = strlen($bodyData) * 8;
    $headerPixelsNeeded = (int) ceil($headerBitCount / 3);
    $bodyPixelsNeeded = (int) ceil($bodyBitCount / (3 * $lsbMode));

    if (($headerPixelsNeeded + $bodyPixelsNeeded) > $totalPixels) {
        imagedestroy($img);
        throw new RuntimeException("Image too small for the selected data and LSB mode.");
    }

    // --- 1. Embed header (sequential, LSB1) ---
    $bitIdx = 0;

    for ($i = 0; $i < $headerPixelsNeeded; $i++) {
        [$r, $g, $b] = get_pixel($img, $i, $width);

        if ($bitIdx < $headerBitCount) {
            $r = ($r & 0xFE) | payload_bit($headerData, $bitIdx++);
        }
        if ($bitIdx < $headerBitCount) {
            $g = ($g & 0xFE) | payload_bit($headerData, $bitIdx++);
        }
        if ($bitIdx < $headerBitCount) {
            $b = ($b & 0xFE) | payload_bit($headerData, $bitIdx++);
        }

        set_pixel($img, $i, $width, $r, $g, $b);
    }

    // --- 2. Embed body (PRNG-shuffled pixels) ---
    $idx = build_shuffle($headerPixelsNeeded, $totalPixels, $bodyPixelsNeeded, $prngSeed);
    $bitIdx = 0;

    for ($k = 0; $k < $bodyPixelsNeeded; $k++) {
        $pixelIndex = packed_index_get($idx, $k);
        [$r, $g, $b] = get_pixel($img, $pixelIndex, $width);

        for ($i = 0; $i < $lsbMode; $i++) {
            if ($bitIdx < $bodyBitCount) {
                $r = ($r & ~(1 << $i)) | (payload_bit($bodyData, $bitIdx++) << $i);
            }
            if ($bitIdx < $bodyBitCount) {
                $g = ($g & ~(1 << $i)) | (payload_bit($bodyData, $bitIdx++) << $i);
            }
            if ($bitIdx < $bodyBitCount) {
                $b = ($b & ~(1 << $i)) | (payload_bit($bodyData, $bitIdx++) << $i);
            }
        }

        set_pixel($img, $pixelIndex, $width, $r, $g, $b);
    }

    unset($idx); // Free memory

    $png = gd_to_png($img);
    imagedestroy($img);
    return $png;
}

/* =========================
   HEADER EXTRACTION
========================= */

function extract_lsb(string $imagePath): array
{
    [$img, $width, $height] = load_image_gd($imagePath);

    $headerPixels = (int) ceil(STEGO_HEADER_BITS / 3);
    $headerBytes = '';
    $currentByte = 0;
    $bitCount = 0;

    for ($i = 0; $i < $headerPixels; $i++) {
        [$r, $g, $b] = get_pixel($img, $i, $width);
        foreach ([$r & 1, $g & 1, $b & 1] as $bit) {
            $currentByte = ($currentByte << 1) | $bit;
            $bitCount++;
            if ($bitCount === 8) {
                $headerBytes .= chr($currentByte);
                $currentByte = 0;
                $bitCount = 0;
            }
        }
    }

    imagedestroy($img);

    return [
        'header_bytes' => substr($headerBytes, 0, STEGO_HEADER_BYTES),
        'header_pixels_used' => $headerPixels,
        'width' => $width,
        'height' => $height,
    ];
}

/* =========================
   BODY EXTRACTION
========================= */

function extract_lsb_body(
    string $imagePath,
    int $headerPixelsUsed,
    int $lsbMode,
    string $prngSeed,
    int $bodyLenBytes
): string {
    if ($lsbMode !== 1 && $lsbMode !== 2) {
        throw new RuntimeException("Invalid LSB mode.");
    }

    [$img, $width, $height] = load_image_gd($imagePath);
    $totalPixels = $width * $height;
    $pixelsNeeded = (int) ceil(($bodyLenBytes * 8) / (3 * $lsbMode));

    $idx = build_shuffle($headerPixelsUsed, $totalPixels, $pixelsNeeded, $prngSeed);
    $bytes = '';
    $bytesRead = 0;
    $currentByte = 0;
    $bitCount = 0;

    for ($k = 0; $k < $pixelsNeeded; $k++) {
        $pixelIndex = packed_index_get($idx, $k);
        [$r, $g, $b] = get_pixel($img, $pixelIndex, $width);

        for ($i = 0; $i < $lsbMode; $i++) {
            foreach ([($r >> $i) & 1, ($g >> $i) & 1, ($b >> $i) & 1] as $bit) {
                $currentByte = ($currentByte << 1) | $bit;
                $bitCount++;
                if ($bitCount === 8) {
                    if ($bytesRead < $bodyLenBytes) {
                        $bytes .= chr($currentByte);
                        $bytesRead++;
                    }
                    $currentByte = 0;
                    $bitCount = 0;
                }
            }
        }
    }

    imagedestroy($img);
    unset($idx);

    return $bytes;
}
