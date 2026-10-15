<?php
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

// SECURITY HEADERS
header("Referrer-Policy: no-referrer");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self'");

// SESSION TIMEOUT EXTENSION (2 Hours)
ini_set('session.gc_maxlifetime', '7200');
$isSecure = app_is_https();
session_set_cookie_params([
    'lifetime' => 7200,
    'path'     => '/',
    'domain'   => '',
    'secure'   => $isSecure,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

require_once __DIR__ . '/db.php';

// HTTPS ENFORCEMENT WITH LOCALHOST EXCEPTION
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

$message = '';
$fatal_error = '';
$token = (string) ($_GET['token'] ?? '');

try {
    if (empty($token) || strlen($token) !== 64) {
        throw new RuntimeException("Security Error: Invalid or missing reset token.");
    }

    $token_hash = hash('sha256', $token);

    $stmt = $pdo->prepare(
        "SELECT email, token_hash, request_ip, user_agent, used
         FROM password_resets
         WHERE token_hash = ? AND expires_at > NOW() AND used = 0"
    );
    $stmt->execute([$token_hash]);
    $resetRow = $stmt->fetch(PDO::FETCH_ASSOC);

    $current_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $current_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);

    if (!$resetRow) {
        throw new RuntimeException("Security Error: Invalid or expired password reset token.");
    }

    if (
        !hash_equals($resetRow['request_ip'] ?? 'UNKNOWN', $current_ip) ||
        !hash_equals($resetRow['user_agent'] ?? 'UNKNOWN', $current_ua)
    ) {
        error_log("Password reset metadata mismatch for token hash: " . $token_hash);
    }

    // RATE LIMITING AGAINST BRUTE FORCE
    $ip = $_SERVER['REMOTE_ADDR'];

    try {
        $pdo->exec("DELETE FROM reset_verify_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

        // 2.7 Opportunistic 30-day purge
        if (random_int(1, 20) === 1) {
            $pdo->exec("DELETE FROM reset_verify_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
        }

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM reset_verify_attempts WHERE ip_address = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->execute([$ip]);
        $verify_attempts = (int) $stmt->fetchColumn();

        if ($verify_attempts >= 10) {
            throw new RuntimeException("Security Error: Request limit exceeded. Please try again later.");
        }

        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);
        $stmt = $pdo->prepare("INSERT INTO reset_verify_attempts (ip_address, user_agent, attempt_time) VALUES (?, ?, NOW())");
        $stmt->execute([$ip, $ua]);
    } catch (\PDOException $e) {
        // Silently swallow missing structure until migration is run
    }

    $email = $resetRow['email'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        $postToken    = $_POST['csrf_token'] ?? '';

        if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
            include 'error_session.php';
            exit;
        }

        $password = $_POST['password'] ?? '';
        $confirm  = $_POST['confirm'] ?? '';

        if ($password !== $confirm) {
            $message = "Passwords do not match.";
        } else {
            $isValidLen = mb_strlen($password) >= 8;
            $hasUpper   = preg_match('/[A-Z]/', $password);
            $hasLower   = preg_match('/[a-z]/', $password);
            $hasNum     = preg_match('/[0-9]/', $password);
            $hasSpecial = preg_match('/[^A-Za-z0-9]/', $password);

            if (!$isValidLen || !$hasUpper || !$hasLower || !$hasNum || !$hasSpecial) {
                $message = "Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.";
            } else {
                $new_password_hash = password_hash($password, PASSWORD_DEFAULT);

                $pdo->beginTransaction();
                try {
                    // C7: Successful password reset marks email as verified
                    $stmt = $pdo->prepare("UPDATE users SET password_hash = ?, email_verified = 1 WHERE email = ?");
                    $stmt->execute([$new_password_hash, $email]);

                    // Prevent replay
                    $stmt = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE email = ? AND token_hash = ?");
                    $stmt->execute([$email, $token_hash]);

                    $pdo->commit();

                    session_unset();
                    session_destroy();

                    header("Location: login.php?reset=1");
                    exit;
                } catch (\PDOException $e) {
                    $pdo->rollBack();
                    error_log("Update Exception on verify_reset.php: " . $e->getMessage());
                    $message = "A system error occurred. Action failed.";
                }
            }
        }
    }
} catch (RuntimeException $e) {
    // A7: Known security exceptions
    $fatal_error = $e->getMessage();
} catch (\PDOException $e) {
    // A7: Database errors logged, generic message to user
    error_log("Fatal DB Error in token verify: " . $e->getMessage());
    $fatal_error = "A local service issue occurred. Please request a new link.";
} catch (Throwable $e) {
    error_log("Unexpected Error in verify_reset: " . $e->getMessage());
    $fatal_error = "An unexpected error occurred. Please request a new link.";
}

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Set New Password | Steganography</title>
    <meta name="description" content="Set a new password for your Steganography account.">
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
            <h1>New Password</h1>
            <p class="auth-status-text">Credential Update Sequence</p>
        </div>

        <?php if ($fatal_error): ?>
            <div class="auth-error-msg" style="margin-bottom: 25px; color: #ff4444; border-color: #ff4444; background: rgba(255, 68, 68, 0.1);">
                <span>
                    <i class="fa-solid fa-triangle-exclamation"></i>
                    <?php echo htmlspecialchars($fatal_error); ?>
                </span>
            </div>

            <div style="text-align: center; margin-top: 30px;">
                <a href="request_reset.php" class="auth-submit-btn" style="text-decoration: none; display: inline-block;">
                    REQUEST NEW LINK &nbsp;<i class="fa-solid fa-arrow-right"></i>
                </a>
            </div>
        <?php else: ?>
            <?php if ($message): ?>
                <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1);">
                    <span>
                        <i class="fa-solid fa-circle-info"></i>
                        <?php echo htmlspecialchars($message); ?>
                    </span>
                </div>
            <?php endif; ?>

            <form id="verifyResetForm" method="POST" action="?token=<?= htmlspecialchars(urlencode($token)) ?>">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                <div class="auth-form-group">
                    <label class="auth-form-label" for="passwordField">New Password</label>
                    <div class="auth-input-wrapper">
                        <i class="fa-solid fa-lock auth-field-icon"></i>
                        <input type="password" name="password" id="passwordField" class="auth-input-field"
                            placeholder="Enter secure password" required autocomplete="new-password">
                        <button type="button" class="auth-toggle-icon" id="togglePassword" aria-label="Show password" aria-controls="passwordField" aria-pressed="false"><i class="fa-solid fa-eye" aria-hidden="true"></i></button>
                    </div>
                    <div class="auth-validation-feedback" id="passwordRules">
                        <span id="rule-length">○ At least 8 characters</span>
                        <span id="rule-upper">○ At least one uppercase letter</span>
                        <span id="rule-lower">○ At least one lowercase letter</span>
                        <span id="rule-number">○ At least one number</span>
                        <span id="rule-special">○ At least one special symbol</span>
                    </div>
                </div>

                <div class="auth-form-group">
                    <label class="auth-form-label" for="confirmPasswordField">Confirm Password</label>
                    <div class="auth-input-wrapper">
                        <i class="fa-solid fa-shield-halved auth-field-icon"></i>
                        <input type="password" name="confirm" id="confirmPasswordField" class="auth-input-field"
                            placeholder="Verify password" required autocomplete="new-password">
                        <button type="button" class="auth-toggle-icon" id="toggleConfirmPassword" aria-label="Show password" aria-controls="confirmPasswordField" aria-pressed="false"><i class="fa-solid fa-eye" aria-hidden="true"></i></button>
                    </div>
                    <div id="matchFeedback" class="auth-match-feedback"></div>
                </div>

                <button type="submit" class="auth-submit-btn">
                    Execute Update
                </button>
            </form>
        <?php endif; ?>
    </div>

    <script src="style.js"></script>
    <script src="verify_reset.js"></script>
</body>
</html>
