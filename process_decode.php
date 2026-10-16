<?php
// ===== process_decode.php =====
// BACKEND CONTROLLER FOR DECODING
declare(strict_types=1);

// Report all errors to the server log but NEVER display them — would corrupt binary ZIP output
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Allow enough memory and time for GD pixel processing on large images
// memory_limit controlled by docker/php.ini
set_time_limit(180);
$operationStartedAt = microtime(true);

register_shutdown_function(static function (): void {
    $lastError = error_get_last();
    $fatalTypes = [E_ERROR, E_CORE_ERROR, E_COMPILE_ERROR, E_PARSE, E_USER_ERROR];

    if ($lastError === null || !in_array($lastError['type'], $fatalTypes, true)) {
        return;
    }

    error_log('Decode fatal error: processing failed');
    while (ob_get_level() > 0) {
        @ob_end_clean();
    }

    if (!headers_sent()) {
        http_response_code(500);
        header('Content-Type: text/plain; charset=UTF-8');
    }

    echo 'Decoding could not be completed. Please use a valid steganographic image and try again.';
});

// Buffer ALL output from this point — cleared before sending binary or error
ob_start();

// ---------------------------------------------------------------
// Top-level handler: catch EVERYTHING including include-time errors
// ---------------------------------------------------------------
try {

    require_once __DIR__ . '/app_config.php';
    require_once 'crypto.php';
    require_once 'prng.php';
    require_once 'payload.php';
    require_once 'lsb.php';

    // Session Start
    if (session_status() === PHP_SESSION_NONE) {
        app_start_session();
    }
    app_enforce_session_timeout(true, true);

    // Discard any stray output from includes before we send headers
    if (ob_get_level()) {
        ob_end_clean();
    }

    // 1. Session Check (Login Required + idle timeout)
    if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
        http_response_code(403);
        exit("Your session expired, please log in again.");
    }

    // Enforce 2-hour server-side idle timeout
    // 2. HTTP Method Check
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit("This action is not available for this request.");
    }

    // 3. CSRF Check — use null-coalescing so missing key never throws TypeError
    $sessionCsrf = $_SESSION['csrf_token'] ?? '';
    $postCsrf = $_POST['csrf_token'] ?? '';
    if (empty($postCsrf) || !hash_equals($sessionCsrf, $postCsrf)) {
        http_response_code(403);
        exit("Your session expired or the page was open too long. Please reload the page and try again.");
    }

    // 4. Input Validation
    if (empty($_FILES['stego_image']) || $_FILES['stego_image']['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException("Stego image upload failed.");
    }

    $stegoPath = $_FILES['stego_image']['tmp_name'];

    // LIMIT: Max 10 MB for stego image (matches encode cover image limit)
    if ($_FILES['stego_image']['size'] > app_max_cover_bytes()) {
        throw new RuntimeException("Stego image too large (Max 10 MB).");
    }

    // Verify it's a valid PNG image using getimagesize()
    $imageInfo = @getimagesize($stegoPath);
    if ($imageInfo === false || $imageInfo[2] !== IMAGETYPE_PNG) {
        $detected = ($imageInfo !== false) ? image_type_to_mime_type($imageInfo[2]) : 'unknown';
        throw new RuntimeException("Stego image must be a valid PNG file. (Detected: $detected)");
    }
    $imagePixels = (int) $imageInfo[0] * (int) $imageInfo[1];
    $maxImagePixels = app_max_image_pixels();
    if ($imagePixels > $maxImagePixels) {
        throw new RuntimeException("Stego image dimensions exceed the {$maxImagePixels}-pixel limit.");
    }

    $stegoOriginalName = mb_substr(basename($_FILES['stego_image']['name'] ?? 'unknown'), 0, 255);
    $imgWidth  = (int) ($imageInfo[0] ?? 0);
    $imgHeight = (int) ($imageInfo[1] ?? 0);

    if (empty($_POST['password'])) {
        throw new RuntimeException("Password is required.");
    }
    $password = $_POST['password'];

    // 5. Extract Header (Sequential LSB1)
    $headerInfo = extract_lsb($stegoPath);
    $headerBytes = $headerInfo['header_bytes'];

    // Parse Header
    $header = parse_header($headerBytes);
    // Header contains: lsb, salt, iv, len, offset

    // SANITY CHECKS (prevent resource exhaustion — real validation is AES-GCM tag)
    if ($header['lsb'] !== 1 && $header['lsb'] !== 2) {
        throw new RuntimeException("Invalid password or corrupted image. (bad LSB mode)");
    }
    // Minimum length check (compressed empty ZIP is >10 bytes)
    if ($header['len'] < 10 || $header['len'] > app_max_secret_bytes()) {
        throw new RuntimeException("Invalid password or corrupted image. (bad payload length)");
    }
    if ($header['len'] > app_payload_capacity_bytes($imgWidth, $imgHeight, $header['lsb'])) {
        throw new RuntimeException("Invalid password or corrupted image.");
    }

    // 6. Derive Key and Seed
    $salt = $header['salt'];
    $derived = derive_master_key($password, $salt);
    $key = substr($derived, 0, 32);
    $prngSeed = substr($derived, 32, 32);

    // 7. Extract Body (Shuffled LSB_MODE)
    // Total body length = ciphertext len + 16 bytes auth tag
    $bodyLen = $header['len'] + 16;

    $bodyBytes = extract_lsb_body(
        $stegoPath,
        $headerInfo['header_pixels_used'],
        $header['lsb'],
        $prngSeed,
        $bodyLen
    );

    // 8. Decrypt
    // Body layout: Ciphertext (len bytes) || Tag (16 bytes)
    $ciphertext = substr($bodyBytes, 0, $header['len']);
    $tag = substr($bodyBytes, $header['len'], 16);
    $iv = $header['iv'];

    $plaintext = aes_decrypt($ciphertext, $key, $iv, $tag);

    // ── DECOMPRESSION: zlib-decompress to recover the original ZIP archive ─────
    // Reverses the gzcompress() applied during encoding.
    $zipData = gzuncompress($plaintext);
    if ($zipData === false) {
        throw new RuntimeException("Decompression failed: data may be corrupt or the password is wrong.");
    }
    // ───────────────────────────────────────────────────────────────────────

    // 9. Log to activity table (non-fatal — must not block ZIP output)
    try {
        require_once 'db.php';
        $pdo->prepare(
            "INSERT INTO user_activity_log
             (user_id, operation, cover_image_name, secret_file_names, lsb_mode, image_width, image_height, performed_at)
             VALUES (?, 'decode', ?, '[]', NULL, ?, ?, NOW())"
        )->execute([
            $_SESSION['user_id'],
            $stegoOriginalName,
            $imgWidth,
            $imgHeight,
        ]);
    } catch (Throwable $logEx) {
        error_log("Decode activity log error: " . $logEx->getMessage());
    }

    error_log(sprintf(
        'Decode complete: pixels=%d lsb=%d payload_bytes=%d elapsed_seconds=%.3f peak_memory_mb=%.2f',
        $imgWidth * $imgHeight,
        $header['lsb'],
        $header['len'] + 16,
        microtime(true) - $operationStartedAt,
        memory_get_peak_usage(true) / 1048576
    ));

    // Output Result
    // Pipeline: LSB extract → AES decrypt → zlib decompress → ZIP output.
    // $zipData now holds the original, uncompressed ZIP archive.
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache');
    header('Content-Type: application/zip');
    header('Content-Disposition: attachment; filename="secret.zip"');
    header('Content-Length: ' . strlen($zipData));
    echo $zipData;
    exit;

} catch (Throwable $e) {
    // Discard any buffered output so only the error message is sent
    if (ob_get_level()) {
        ob_end_clean();
    }
    http_response_code(400);
    $msg = $e->getMessage();
    if (empty($msg)) {
        $msg = '[' . get_class($e) . '] (no message) in ' . basename($e->getFile()) . ':' . $e->getLine();
    }
    echo $msg;
    exit;
}
