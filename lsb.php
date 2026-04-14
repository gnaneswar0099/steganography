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
|  - SplFixedArray for shuffle index list (saves ~4x memory vs PHP array)
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

function bytes_to_bits(string $data): array
{
    $bits = [];
    $len = strlen($data);
    for ($i = 0; $i < $len; $i++) {
        $byte = ord($data[$i]);
        for ($j = 7; $j >= 0; $j--) {
            $bits[] = ($byte >> $j) & 1;
        }
    }
    return $bits;
}

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
 * Uses SplFixedArray to reduce memory vs a plain PHP array.
 *
 * @param int $start        First available pixel index (after header)
 * @param int $total        Total pixel count of image
 * @param int $needed       How many shuffled slots we actually need
 * @param string $prngSeed  32-byte binary seed
 * @return SplFixedArray    Indices [0..$needed-1] are the selected pixels
 */
function build_shuffle(int $start, int $total, int $needed, string $prngSeed): SplFixedArray
{
    $count = $total - $start;

    // SplFixedArray uses ~4x less memory than a PHP hash-array of integers
    $idx = new SplFixedArray($count);
    for ($i = 0; $i < $count; $i++) {
        $idx[$i] = $start + $i;
    }

    $prngCounter = 0;
    for ($i = 0; $i < $needed; $i++) {
        $j = $i + prng_int($prngSeed, $prngCounter++, $count - $i - 1);
        // swap
        $tmp = $idx[$i];
        $idx[$i] = $idx[$j];
        $idx[$j] = $tmp;
    }

    return $idx;
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

    // Split payload into header (33 bytes) + body
    $headerBits = bytes_to_bits(substr($payload, 0, STEGO_HEADER_BYTES));
    $bodyBits = bytes_to_bits(substr($payload, STEGO_HEADER_BYTES));

    $headerPixelsNeeded = (int) ceil(count($headerBits) / 3);
    $bodyPixelsNeeded = (int) ceil(count($bodyBits) / (3 * $lsbMode));

    if (($headerPixelsNeeded + $bodyPixelsNeeded) > $totalPixels) {
        imagedestroy($img);
        throw new RuntimeException("Image too small for the selected data and LSB mode.");
    }

    // --- 1. Embed header (sequential, LSB1) ---
    $bitIdx = 0;
    $hCount = count($headerBits);

    for ($i = 0; $i < $headerPixelsNeeded; $i++) {
        [$r, $g, $b] = get_pixel($img, $i, $width);

        if ($bitIdx < $hCount) {
            $r = ($r & 0xFE) | $headerBits[$bitIdx++];
        }
        if ($bitIdx < $hCount) {
            $g = ($g & 0xFE) | $headerBits[$bitIdx++];
        }
        if ($bitIdx < $hCount) {
            $b = ($b & 0xFE) | $headerBits[$bitIdx++];
        }

        set_pixel($img, $i, $width, $r, $g, $b);
    }

    // --- 2. Embed body (PRNG-shuffled pixels) ---
    $idx = build_shuffle($headerPixelsNeeded, $totalPixels, $bodyPixelsNeeded, $prngSeed);
    $bitIdx = 0;
    $bCount = count($bodyBits);

    for ($k = 0; $k < $bodyPixelsNeeded; $k++) {
        [$r, $g, $b] = get_pixel($img, $idx[$k], $width);

        for ($i = 0; $i < $lsbMode; $i++) {
            if ($bitIdx < $bCount) {
                $r = ($r & ~(1 << $i)) | ($bodyBits[$bitIdx++] << $i);
            }
            if ($bitIdx < $bCount) {
                $g = ($g & ~(1 << $i)) | ($bodyBits[$bitIdx++] << $i);
            }
            if ($bitIdx < $bCount) {
                $b = ($b & ~(1 << $i)) | ($bodyBits[$bitIdx++] << $i);
            }
        }

        set_pixel($img, $idx[$k], $width, $r, $g, $b);
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
    $bits = [];

    for ($i = 0; $i < $headerPixels; $i++) {
        [$r, $g, $b] = get_pixel($img, $i, $width);
        $bits[] = $r & 1;
        $bits[] = $g & 1;
        $bits[] = $b & 1;
    }

    imagedestroy($img);

    return [
        'header_bytes' => bits_to_bytes(array_slice($bits, 0, STEGO_HEADER_BITS)),
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
    $bits = [];

    for ($k = 0; $k < $pixelsNeeded; $k++) {
        [$r, $g, $b] = get_pixel($img, $idx[$k], $width);

        for ($i = 0; $i < $lsbMode; $i++) {
            $bits[] = ($r >> $i) & 1;
            $bits[] = ($g >> $i) & 1;
            $bits[] = ($b >> $i) & 1;
        }
    }

    imagedestroy($img);
    unset($idx);

    return bits_to_bytes(array_slice($bits, 0, $bodyLenBytes * 8));
}
