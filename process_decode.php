<?php
// ===== process_decode.php =====
// BACKEND CONTROLLER FOR DECODING
declare(strict_types=1);

// Report all errors to the server log but NEVER display them — would corrupt binary ZIP output
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Allow enough memory and time for GD pixel processing on large images
ini_set('memory_limit', '512M');
set_time_limit(180);

// Buffer ALL output from this point — cleared before sending binary or error
ob_start();

// ---------------------------------------------------------------
// Top-level handler: catch EVERYTHING including include-time errors
// ---------------------------------------------------------------
try {

    require_once 'crypto.php';
    require_once 'prng.php';
    require_once 'payload.php';
    require_once 'lsb.php';

    // Session Start
    if (session_status() === PHP_SESSION_NONE) {
        session_start();
    }

    // Discard any stray output from includes before we send headers
    if (ob_get_level()) {
        ob_end_clean();
    }

    // 1. Session Check (Login Required + idle timeout)
    if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
        http_response_code(403);
        exit("Access Denied: You must be logged in.");
    }

    // Enforce 2-hour server-side idle timeout
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 7200)) {
        session_unset();
        session_destroy();
        http_response_code(401);
        exit("Session expired. Please log in again.");
    }
    $_SESSION['last_activity'] = time(); // Rolling update

    // 2. HTTP Method Check
    if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
        http_response_code(405);
        exit("Method Not Allowed");
    }

    // 3. CSRF Check — use null-coalescing so missing key never throws TypeError
    $sessionCsrf = $_SESSION['csrf_token'] ?? '';
    $postCsrf = $_POST['csrf_token'] ?? '';
    if (empty($postCsrf) || !hash_equals($sessionCsrf, $postCsrf)) {
        http_response_code(403);
        exit("Invalid CSRF Token");
    }

    // 4. Input Validation
    if (empty($_FILES['stego_image']) || $_FILES['stego_image']['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException("Stego image upload failed.");
    }

    $stegoPath = $_FILES['stego_image']['tmp_name'];

    // LIMIT: Max 20 MB for stego image (matches encode cover image limit)
    if ($_FILES['stego_image']['size'] > 20 * 1024 * 1024) {
        throw new RuntimeException("Stego image too large (Max 20 MB).");
    }

    // Verify it's a valid PNG image using getimagesize()
    $imageInfo = @getimagesize($stegoPath);
    if ($imageInfo === false || $imageInfo[2] !== IMAGETYPE_PNG) {
        $detected = ($imageInfo !== false) ? image_type_to_mime_type($imageInfo[2]) : 'unknown';
        throw new RuntimeException("Stego image must be a valid PNG file. (Detected: $detected)");
    }

    $stegoOriginalName = basename($_FILES['stego_image']['name'] ?? 'unknown');
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
    if ($header['len'] < 10 || $header['len'] > 20 * 1024 * 1024) {
        throw new RuntimeException("Invalid password or corrupted image. (bad payload length)");
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
