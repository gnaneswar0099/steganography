<?php
// ===== verify_email.php =====
// Email verification handler: GET displays confirmation page, POST performs activation.
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

// Security headers
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

$token = trim((string)($_GET['token'] ?? ($_POST['token'] ?? '')));
$status = 'pending'; // 'pending' | 'success' | 'error'
$message = '';

if (!$emailVerificationRequired) {
    $status = 'error';
    $message = 'Email verification is not enabled.';
} elseif (empty($token) || strlen($token) !== 64) {
    $status = 'error';
    $message = 'Invalid or missing verification token.';
} else {
    $token_hash = hash('sha256', $token);

    try {
        // Opportunistic cleanup of expired verification records
        if (random_int(1, 20) === 1) {
            $pdo->exec("DELETE FROM email_verifications WHERE expires_at < NOW()");
        }

        // Look up token
        $stmt = $pdo->prepare(
            "SELECT email, expires_at FROM email_verifications WHERE token_hash = ? AND expires_at > NOW()"
        );
        $stmt->execute([$token_hash]);
        $row = $stmt->fetch(PDO::FETCH_ASSOC);

        if (!$row) {
            $status = 'error';
            $message = 'Activation link is invalid, expired, or has already been used.';
        } elseif ($_SERVER['REQUEST_METHOD'] === 'POST') {
            // C4: Verify on POST with CSRF
            $sessionToken = $_SESSION['csrf_token'] ?? '';
            $postToken    = $_POST['csrf_token'] ?? '';

            if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
                include 'error_session.php';
                exit;
            }

            $email = $row['email'];

            $pdo->beginTransaction();
            try {
                // Update user and consume this exact token atomically.
                $updateUser = $pdo->prepare("UPDATE users SET email_verified = 1 WHERE email = ?");
                $updateUser->execute([$email]);

                $deleteToken = $pdo->prepare("DELETE FROM email_verifications WHERE token_hash = ?");
                $deleteToken->execute([$token_hash]);
                if ($deleteToken->rowCount() !== 1) {
                    $pdo->rollBack();
                    $status = 'error';
                    $message = 'Activation link is invalid, expired, or has already been used.';
                } else {
                    $pdo->commit();
                    $status = 'success';
                    $message = 'Your email has been verified successfully! Your account is now active.';
                }
            } catch (PDOException $e) {
                if ($pdo->inTransaction()) {
                    $pdo->rollBack();
                }
                error_log("Error during email activation: " . $e->getMessage());
                $status = 'error';
                $message = 'A system error occurred while activating your account. Please try again.';
            }
        }
    } catch (PDOException $e) {
        error_log("Error in verify_email: " . $e->getMessage());
        $status = 'error';
        $message = 'Verification service temporarily unavailable.';
    }
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Email Verification - Steganography</title>
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
            <h1>Email Verification</h1>
            <p class="auth-status-text">Account Activation Sequence</p>
        </div>

        <?php if ($status === 'success'): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1); margin-bottom: 25px;">
                <span>
                    <i class="fa-solid fa-circle-check"></i>
                    <?= htmlspecialchars($message) ?>
                </span>
            </div>
            <div style="text-align: center; margin-top: 25px;">
                <a href="login.php?verified=1" class="auth-submit-btn" style="text-decoration: none; display: inline-block;">
                    CONTINUE TO SIGN IN &nbsp;<i class="fa-solid fa-arrow-right"></i>
                </a>
            </div>
        <?php elseif ($status === 'error'): ?>
            <div class="auth-error-msg" style="margin-bottom: 25px; color: #ff4444; border-color: #ff4444; background: rgba(255, 68, 68, 0.1);">
                <span>
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <?= htmlspecialchars($message) ?>
                </span>
            </div>
            <div style="text-align: center; margin-top: 25px;">
                <a href="resend_verification.php" class="auth-submit-btn" style="text-decoration: none; display: inline-block;">
                    REQUEST NEW ACTIVATION LINK &nbsp;<i class="fa-solid fa-rotate-right"></i>
                </a>
            </div>
        <?php else: ?>
            <!-- GET Confirmation Page (Requires User Click -> POST) -->
            <div class="auth-error-msg" style="color: #00ffff; border-color: #00ffff; background: rgba(0, 255, 255, 0.08); margin-bottom: 25px;">
                <span>
                    <i class="fa-solid fa-shield-halved"></i>
                    Click the button below to confirm your email and activate your account.
                </span>
            </div>
            <form method="POST" action="verify_email.php?token=<?= htmlspecialchars(urlencode($token)) ?>">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">
                <input type="hidden" name="token" value="<?= htmlspecialchars($token) ?>">

                <button type="submit" class="auth-submit-btn">
                    <i class="fa-solid fa-check"></i> ACTIVATE ACCOUNT NOW
                </button>
            </form>
        <?php endif; ?>
    </div>

    <script src="style.js"></script>
</body>
</html>
