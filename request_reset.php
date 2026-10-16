<?php
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';
require_once __DIR__ . '/mailer.php';

// 8. SECURITY HEADERS
header("Referrer-Policy: no-referrer");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self'");

// 9. Session setup
app_start_session();
app_enforce_session_timeout();
$isSecure = app_is_https();

// Ensure db.php is required for $pdo instance
require_once __DIR__ . '/db.php';

// 1. HTTPS ENFORCEMENT WITH LOCALHOST EXCEPTION
$isLocalhost = in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1']) || str_contains($_SERVER['HTTP_HOST'], 'localhost') || str_contains($_SERVER['HTTP_HOST'], '127.0.0.1');
if (!$isSecure && !$isLocalhost) {
    try {
        $redirect_url = app_public_origin() . ($_SERVER['REQUEST_URI'] ?? '/');
    } catch (RuntimeException $e) {
        error_log("Link build failed: invalid or missing APP_URL");
        $redirect_url = null;
    }
    if ($redirect_url !== null) {
        header("Location: $redirect_url", true, 301);
        exit();
    }
}

// ANTI-ENUMERATION PROTECTION
$generic_message = "If the email exists, a password reset link has been sent.";
$message = '';

// 1. CSRF TOKEN - generated BEFORE POST block
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 13. CSRF PROTECTION
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    $postToken    = $_POST['csrf_token'] ?? '';

    if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
        include 'error_session.php';
        exit;
    }

    $email = trim($_POST['email'] ?? '');
    if (strlen($email) > 255) {
        $email = '';
    }

    // 10. EMAIL INPUT VALIDATION
    if (strlen($email) <= 255 && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        try {
            // 3. EXPIRED TOKEN CLEANUP
            $pdo->exec("DELETE FROM password_resets WHERE expires_at < NOW()");

            // 4. RATE-LIMIT TABLE CLEANUP (24 hours)
            $pdo->exec("DELETE FROM password_reset_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

            // 2.7 OPPORTUNISTIC 30-DAY PURGE
            if (random_int(1, 20) === 1) {
                $pdo->exec("DELETE FROM password_reset_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            }

            // 5. MAINTAIN RATE LIMITING (Max 3 queries per hour per email address)
            $stmt = $pdo->prepare("
                SELECT COUNT(*)
                FROM password_reset_attempts
                WHERE email = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ");
            $stmt->execute([$email]);
            $attempts = (int) $stmt->fetchColumn();

            if ($attempts < 3) {
                // Log attempt
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
                $stmt = $pdo->prepare("INSERT INTO password_reset_attempts (email, attempt_time, ip_address) VALUES (?, NOW(), ?)");
                $stmt->execute([$email, $ip]);

                // Look up user
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);

                if ($stmt->fetch()) {
                    // Token generation
                    $token = bin2hex(random_bytes(32));
                    $token_hash = hash('sha256', $token);

                    $capture_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
                    $capture_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);

                    // Clear previous tokens
                    $stmt = $pdo->prepare("DELETE FROM password_resets WHERE email = ?");
                    $stmt->execute([$email]);

                    // Insert new token (30 min expiry)
                    $stmt = $pdo->prepare("
                        INSERT INTO password_resets (email, token_hash, expires_at, request_ip, user_agent)
                        VALUES (?, ?, NOW() + INTERVAL 30 MINUTE, ?, ?)
                    ");
                    $stmt->execute([$email, $token_hash, $capture_ip, $capture_ua]);

                    // Reset link
                    $base_dir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
                    $reset_link = null;
                    try {
                        $reset_link = app_public_origin() . $base_dir . "/verify_reset.php?token=" . urlencode($token);
                    } catch (RuntimeException $e) {
                        error_log("Link build failed: invalid or missing APP_URL");
                    }

                    if ($reset_link !== null) {
                        $subject = 'Secure Password Reset';
                        $htmlBody = "A password reset request was received for your account.<br><br>"
                                  . "If you initiated this request, click the link below to reset your password:<br><br>"
                                  . "<a href='" . htmlspecialchars($reset_link, ENT_QUOTES, 'UTF-8') . "' style='color:#00ffff; font-weight:bold;'>Reset Password</a><br><br>"
                                  . "This link will expire in 30 minutes.<br><br>"
                                  . "If you did not request this, please ignore this email.";

                        $altBody  = "A password reset request was received for your account.\n\n"
                                  . "If you initiated this request, copy and paste the link below to reset your password:\n\n"
                                  . "{$reset_link}\n\n"
                                  . "This link will expire in 30 minutes.\n\n"
                                  . "If you did not request this, please ignore this email.";

                        send_system_email($email, $subject, $htmlBody, $altBody);
                    }
                }
            }
        } catch (PDOException $e) {
            error_log("DB Error in request_reset: " . $e->getMessage());
        }
    }
    // Anti-enumeration protection - always generic message
    $message = $generic_message;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password | Steganography</title>
    <meta name="description" content="Request a secure password reset link.">
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link rel="stylesheet" href="style.css?v=<?= filemtime('style.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= filemtime('auth.css') ?>">
    <link rel="stylesheet" href="nav.css?v=<?= filemtime('nav.css') ?>">
</head>
<body>
    <div class="grid-container" id="gridContainer"></div>
    <?php
    $isLoggedIn = false;
    $username   = '';
    $activeNav  = '';
    ?>
    <?php include 'nav.php'; ?>

    <div class="auth-login-container">
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1>Recovery Portal</h1>
            <p class="auth-status-text">Password Reset Pipeline</p>
        </div>

        <?php if ($message): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1);">
                <span>
                    <i class="fa-solid fa-circle-info"></i>
                    <?php echo htmlspecialchars($message); ?>
                </span>
            </div>
        <?php endif; ?>

        <form id="requestResetForm" method="POST" action="request_reset.php">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            <div class="auth-form-group">
                <label class="auth-form-label" for="emailField">Account Email</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-envelope auth-field-icon"></i>
                    <input type="email" name="email" id="emailField" class="auth-input-field"
                           placeholder="Enter registered email" required autocomplete="email" maxlength="255">
                </div>
            </div>

            <button type="submit" class="auth-submit-btn">
                Send Reset Link
            </button>
        </form>

        <div class="auth-register-link">
            Remember credentials? <a href="login.php">Back to Login</a>
        </div>
    </div>

    <script src="style.js"></script>
    <script src="request_reset.js"></script>
</body>
</html>
