<?php
// ===== process_encode.php =====
// BACKEND CONTROLLER FOR ENCODING
declare(strict_types=1);

// Report all errors to the server log but NEVER display them — would corrupt binary PNG output
error_reporting(E_ALL);
ini_set('display_errors', '0');
ini_set('log_errors', '1');

// Allow enough memory and time for GD pixel processing on large images
ini_set('memory_limit', '512M');
ini_set('upload_max_filesize', '50M');
ini_set('post_max_size', '50M');
ini_set('max_input_time', '300');
ini_set('max_execution_time', '300');
set_time_limit(300);

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

    // 3. CSRF Check — null-coalescing prevents TypeError on missing session key
    $sessionCsrf = $_SESSION['csrf_token'] ?? '';
    $postCsrf = $_POST['csrf_token'] ?? '';
    if (empty($postCsrf) || !hash_equals($sessionCsrf, $postCsrf)) {
        http_response_code(403);
        exit("Invalid CSRF Token");
    }

    // 4. Input Validation
    if (empty($_FILES['cover_image']) || $_FILES['cover_image']['error'] !== UPLOAD_ERR_OK) {
        throw new RuntimeException("Cover image upload failed.");
    }

    $coverOriginalName = basename($_FILES['cover_image']['name'] ?? 'unknown');
    $coverPath = $_FILES['cover_image']['tmp_name'];

    // Verify it's a valid PNG or JPEG using getimagesize()
    $imageInfo = @getimagesize($coverPath);
    if ($imageInfo === false || ($imageInfo[2] !== IMAGETYPE_PNG && $imageInfo[2] !== IMAGETYPE_JPEG)) {
        $detected = ($imageInfo !== false) ? image_type_to_mime_type($imageInfo[2]) : 'unknown';
        throw new RuntimeException("Cover image must be PNG or JPEG. (Detected: $detected)");
    }

    // Limit cover image to 20 MB to prevent memory exhaustion during GD processing
    if ($_FILES['cover_image']['size'] > 20 * 1024 * 1024) {
        throw new RuntimeException("Cover image too large. Maximum allowed size is 20 MB.");
    }

    if (empty($_POST['password'])) {
        throw new RuntimeException("Password is required.");
    }
    $password = $_POST['password'];

    $lsbMode = (int) ($_POST['lsb_method'] ?? 1);
    if ($lsbMode !== 1 && $lsbMode !== 2) {
        throw new RuntimeException("Invalid LSB mode.");
    }

    // 5. Process Secret Files (Zip them)
    if (empty($_FILES['secret_files'])) {
        throw new RuntimeException("No secret files provided.");
    }

    $files = $_FILES['secret_files'];
    if (!isset($files['name']) || !is_array($files['name'])) {
        throw new RuntimeException("Invalid file upload format.");
    }

    $fileCount = count($files['name']);
    if ($fileCount > 15) {
        throw new RuntimeException("Too many files. Max 15 allowed.");
    }

    $totalSize = 0;
    foreach ($files['size'] as $s) {
        $totalSize += (int) $s;
    }
    if ($totalSize > 10 * 1024 * 1024) {
        throw new RuntimeException("Total file size exceeds 10 MB.");
    }

    // Create a temporary zip file
    $tempZipPath = tempnam(sys_get_temp_dir(), 'stegzip');
    $zip = new ZipArchive();

    if ($zip->open($tempZipPath, ZipArchive::CREATE | ZipArchive::OVERWRITE) !== true) {
        throw new RuntimeException("Cannot create zip archive.");
    }

    $secretFileNames = [];
    for ($i = 0; $i < $fileCount; $i++) {
        if ($files['error'][$i] === UPLOAD_ERR_OK) {
            $rawName = basename($files['name'][$i]);
            $safeName = preg_replace('/[^a-zA-Z0-9._-]/', '_', $rawName);
            $zip->addFile($files['tmp_name'][$i], $safeName);
            $secretFileNames[] = $safeName;
        }
    }
    $zip->close();

    $zipBytes = file_get_contents($tempZipPath);
    @unlink($tempZipPath);

    if ($zipBytes === false || strlen($zipBytes) === 0) {
        throw new RuntimeException("Failed to read secret data from archive.");
    }

    // ── COMPRESSION: zlib-compress the ZIP archive before encryption ──────────
    // Level 9 = maximum compression. Reduces payload size embedded in image.
    $plaintext = gzcompress($zipBytes, 9);
    if ($plaintext === false) {
        throw new RuntimeException("Compression failed: gzcompress() returned false.");
    }
    // ─────────────────────────────────────────────────────────────────────────

    // 6. Capacity Check
    $imgDims = @getimagesize($coverPath);
    if (!$imgDims || $imgDims[0] <= 0 || $imgDims[1] <= 0) {
        throw new RuntimeException("Invalid image dimensions.");
    }
    $width = $imgDims[0];
    $height = $imgDims[1];
    $totalPixels = $width * $height;

    // Header: 33 bytes × 8 bits, stored LSB1 (3 bits/pixel)
    $headerPixels = (int) ceil((33 * 8) / 3);                          // = 88

    // Body: (compressed plaintext + AES tag) × 8 bits, stored at lsbMode bits/channel
    $bodyBytes = strlen($plaintext) + 16; // +16 for GCM auth tag (plaintext is now compressed)
    $bodyPixels = (int) ceil(($bodyBytes * 8) / (3 * $lsbMode));

    if (($headerPixels + $bodyPixels) > $totalPixels) {
        $msg = "Image is too small for this data.";
        $msg .= ($lsbMode === 1)
            ? " Try switching to 'Storing in My Device' mode or use a larger image."
            : " Please use a larger image.";
        throw new RuntimeException($msg);
    }

    // 7. Cryptography
    $salt = random_bytes(16);
    $derived = derive_master_key($password, $salt);   // 64 bytes
    $key = substr($derived, 0, 32);
    $prngSeed = substr($derived, 32, 32);
    $iv = random_bytes(12);

    [$ciphertext, $tag] = aes_encrypt($plaintext, $key, $iv);

    $payload = build_payload($lsbMode, $salt, $iv, $ciphertext, $tag);

    // 8. Embed into Image
    $stegoImageData = embed_lsb($coverPath, $payload, $lsbMode, $prngSeed);

    if (empty($stegoImageData)) {
        throw new RuntimeException("Embedding failed: produced empty output.");
    }

    // 9. Log to activity table (non-fatal — must not block PNG output)
    try {
        require_once 'db.php';
        $pdo->prepare(
            "INSERT INTO user_activity_log
             (user_id, operation, cover_image_name, secret_file_names, lsb_mode, image_width, image_height, performed_at)
             VALUES (?, 'encode', ?, ?, ?, ?, ?, NOW())"
        )->execute([
            $_SESSION['user_id'],
            $coverOriginalName,
            json_encode($secretFileNames),
            $lsbMode,
            $width,
            $height,
        ]);
    } catch (Throwable $logEx) {
        error_log("Encode activity log error: " . $logEx->getMessage());
    }

    // Output — send the PNG
    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    header('Cache-Control: post-check=0, pre-check=0', false);
    header('Pragma: no-cache');
    header('Content-Type: image/png');
    header('Content-Disposition: attachment; filename="stego_image.png"');
    header('Content-Length: ' . strlen($stegoImageData));
    echo $stegoImageData;
    exit;

} catch (Throwable $e) {
    // Garbage collection: Ensure temp zip files are deleted even if an exception crashes the script
    if (isset($tempZipPath) && file_exists($tempZipPath)) {
        @unlink($tempZipPath);
    }

    // Discard any buffered output so only the clean error message is sent
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

