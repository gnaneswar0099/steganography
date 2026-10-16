<?php
// ===== resend_verification.php =====
// Request a new email activation link. Rate-limited and anti-enumeration protected.
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';
require_once __DIR__ . '/mailer.php';

header("Referrer-Policy: no-referrer");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self'");

if (session_status() === PHP_SESSION_NONE) {
    app_start_session();
}
app_enforce_session_timeout();

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$emailVerificationRequired = app_email_verification_required();
if ($emailVerificationRequired) {
    require_once __DIR__ . '/db.php';
}

$generic_msg = "If an unverified account exists with that email address, a new activation link has been sent.";
$message = $emailVerificationRequired ? '' : 'Email verification is not enabled.';
$prefill_email = trim((string)($_GET['email'] ?? ''));

if ($emailVerificationRequired && $_SERVER['REQUEST_METHOD'] === 'POST') {
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    $postToken    = $_POST['csrf_token'] ?? '';

    if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
        include 'error_session.php';
        exit;
    }

    $email = trim((string)($_POST['email'] ?? ''));

    if (strlen($email) <= 255 && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        try {
            $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';

            // Clean up old attempts > 24 hours
            $pdo->exec("DELETE FROM email_verification_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

            // 2.7 Opportunistic 30-day purge
            if (random_int(1, 20) === 1) {
                $pdo->exec("DELETE FROM email_verification_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            }

            // Rate limit: max 3 per hour per email/IP
            $rateStmt = $pdo->prepare(
                "SELECT COUNT(*) FROM email_verification_attempts
                 WHERE (email = ? OR ip_address = ?) AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)"
            );
            $rateStmt->execute([$email, $ip]);
            $attempts = (int) $rateStmt->fetchColumn();

            if ($attempts < 3) {
                // Log attempt
                $logStmt = $pdo->prepare(
                    "INSERT INTO email_verification_attempts (email, ip_address, attempt_time) VALUES (?, ?, NOW())"
                );
                $logStmt->execute([$email, $ip]);

                // Check for unverified user
                $uStmt = $pdo->prepare("SELECT id, username, email_verified FROM users WHERE email = ?");
                $uStmt->execute([$email]);
                $user = $uStmt->fetch(PDO::FETCH_ASSOC);

                if ($user && (int)($user['email_verified'] ?? 0) !== 1) {
                    $token      = bin2hex(random_bytes(32));
                    $token_hash = hash('sha256', $token);

                    $pdo->beginTransaction();
                    $pdo->prepare("DELETE FROM email_verifications WHERE email = ?")->execute([$email]);

                    $insStmt = $pdo->prepare(
                        "INSERT INTO email_verifications (email, token_hash, expires_at)
                         VALUES (?, ?, NOW() + INTERVAL 24 HOUR)"
                    );
                    $insStmt->execute([$email, $token_hash]);
                    $pdo->commit();

                    $base_dir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
                    $activationLink = null;
                    try {
                        $activationLink = app_public_origin() . $base_dir . "/verify_email.php?token=" . urlencode($token);
                    } catch (RuntimeException $e) {
                        error_log("Link build failed: invalid or missing APP_URL");
                    }

                    if ($activationLink !== null) {
                        $subject  = "Activate your Steganography Account (New Link)";
                        $htmlBody = "Hello " . htmlspecialchars($user['username'], ENT_QUOTES, 'UTF-8') . ",<br><br>"
                                  . "A new activation link was requested for your account.<br><br>"
                                  . "<a href='" . htmlspecialchars($activationLink, ENT_QUOTES, 'UTF-8') . "' style='display:inline-block;padding:10px 20px;background:#00ffff;color:#000;font-weight:bold;text-decoration:none;border-radius:4px;'>ACTIVATE ACCOUNT</a><br><br>"
                                  . "Or copy and paste this link:<br>"
                                  . htmlspecialchars($activationLink, ENT_QUOTES, 'UTF-8') . "<br><br>"
                                  . "This link will expire in 24 hours.";

                        $textBody = "Hello {$user['username']},\n\n"
                                  . "A new activation link was requested for your account:\n\n"
                                  . "{$activationLink}\n\n"
                                  . "This link will expire in 24 hours.";

                        send_system_email($email, $subject, $htmlBody, $textBody);
                    }
                }
            }
        } catch (PDOException $e) {
            error_log("Error in resend_verification: " . $e->getMessage());
        }
    }

    $message = $generic_msg;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Resend Activation - Steganography</title>
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
            <h1>Resend Activation</h1>
            <p class="auth-status-text">Account Verification Dispatch</p>
        </div>

        <?php if ($message): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1); margin-bottom: 25px;">
                <span>
                    <i class="fa-solid fa-circle-info"></i>
                    <?= htmlspecialchars($message) ?>
                </span>
            </div>
        <?php endif; ?>

        <form method="POST" action="resend_verification.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            <div class="auth-form-group">
                <label class="auth-form-label">Account Email</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-envelope auth-field-icon"></i>
                    <input type="email" name="email" class="auth-input-field"
                           placeholder="Enter registered email" required
                           value="<?= htmlspecialchars($prefill_email ?: ($_POST['email'] ?? '')) ?>"
                           autocomplete="email" maxlength="255">
                </div>
            </div>

            <button type="submit" class="auth-submit-btn">
                Send New Activation Link
            </button>
        </form>

        <div class="auth-register-link">
            Already verified? <a href="login.php">Back to Login</a>
        </div>
    </div>

    <script src="style.js"></script>
</body>
</html>
