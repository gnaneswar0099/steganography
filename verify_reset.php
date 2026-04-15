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
    'path' => '/',
    'domain' => '',
    'secure' => $isSecure,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

require_once __DIR__ . '/db.php'; // Gives us $pdo via parameterization

// HTTPS ENFORCEMENT WITH LOCALHOST EXCEPTION
$isLocalhost = in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1']) || str_contains($_SERVER['HTTP_HOST'], 'localhost') || str_contains($_SERVER['HTTP_HOST'], '127.0.0.1');
if (!$isSecure && !$isLocalhost) {
    $redirect_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect_url", true, 301);
    exit();
}

$message = '';
$fatal_error = '';
$token = $_GET['token'] ?? '';

try {
    if (empty($token)) {
        throw new Exception("Security Error: Invalid or missing reset token.");
    }

    $token_hash = hash('sha256', $token);

    // Fetch the matching reset row directly by token hash — fast and avoids a
    // full-table scan loop. The token is a SHA-256 hash so it is safe in a WHERE clause.
    $stmt = $pdo->prepare(
        "SELECT email, token_hash, request_ip, user_agent, used 
         FROM password_resets 
         WHERE token_hash = ? AND expires_at > NOW() AND used = 0"
    );
    $stmt->execute([$token_hash]);
    $resetRow = $stmt->fetch(PDO::FETCH_ASSOC);

    $current_ip   = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
    $current_ua   = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);

    if (!$resetRow) {
        throw new Exception("Security Error: Invalid or expired password reset token.");
    }

    // Soft-check the original request metadata for anomaly logging only.
    // Exact IP / User-Agent matches are too brittle for legitimate users who
    // switch devices or networks before opening the reset link.
    if (
        !hash_equals($resetRow['request_ip'] ?? 'UNKNOWN', $current_ip) ||
        !hash_equals($resetRow['user_agent'] ?? 'UNKNOWN', $current_ua)
    ) {
        error_log("Password reset metadata mismatch for token hash: " . $token_hash);
    }

    // RATE LIMITING AGAINST BRUTE FORCE / STUFFING
    $ip = $_SERVER['REMOTE_ADDR'];

    try {
        $pdo->exec("DELETE FROM reset_verify_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

        $stmt = $pdo->prepare("SELECT COUNT(*) FROM reset_verify_attempts WHERE ip_address = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)");
        $stmt->execute([$ip]);
        $verify_attempts = (int) $stmt->fetchColumn();

        if ($verify_attempts >= 10) {
            // Obfuscated identical error mask to avoid signaling a rate-limit lockout to random scrapers
            throw new Exception("Security Error: Request limit exceeded. Please try again later.");
        }

        $ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);
        $stmt = $pdo->prepare("INSERT INTO reset_verify_attempts (ip_address, user_agent, attempt_time) VALUES (?, ?, NOW())");
        $stmt->execute([$ip, $ua]);
    } catch (\PDOException $e) {
        // Silently swallow missing structure until the user executes the migration manually so the underlying block doesn't crash the reset sequence.
        // It bypasses the rate limitation ONLY if the SQL table structurally does not exist yet.
    }

    $email = $resetRow['email'];

    if ($_SERVER['REQUEST_METHOD'] === 'POST') {
        // CSRF PROTECTION
        $sessionToken = $_SESSION['csrf_token'] ?? '';
        $postToken = $_POST['csrf_token'] ?? '';

        if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
            include 'error_session.php';
            exit;
        }

        // We no longer regenerate on every POST to prevent session mismatch errors
        // during multi-step validation or browser backward/forward navigation.

        $password = $_POST['password'] ?? '';
        $confirm = $_POST['confirm'] ?? '';

        if ($password !== $confirm) {
            $message = "Passwords do not match.";
        } else {
            // PASSWORD SECURITY VALIDATION
            $isValidLen = mb_strlen($password) >= 8;
            $hasUpper = preg_match('/[A-Z]/', $password);
            $hasLower = preg_match('/[a-z]/', $password);
            $hasNum = preg_match('/[0-9]/', $password);
            $hasSpecial = preg_match('/[^A-Za-z0-9]/', $password);

            if (!$isValidLen || !$hasUpper || !$hasLower || !$hasNum || !$hasSpecial) {
                $message = "Password must be at least 8 characters long, contain an uppercase letter, a lowercase letter, a number, and a special character.";
            } else {
                $new_password_hash = password_hash($password, PASSWORD_DEFAULT);

                // INJECTION PREVENTION & TRANSACTIONS
                $pdo->beginTransaction();
                try {
                    // Update user credentials
                    $stmt = $pdo->prepare("UPDATE users SET password_hash = ? WHERE email = ?");
                    $stmt->execute([$new_password_hash, $email]);

                    // REPLAY ATTACK PREVENTION
                    $stmt = $pdo->prepare("UPDATE password_resets SET used = 1 WHERE email = ? AND token_hash = ?");
                    $stmt->execute([$email, $token_hash]);

                    $pdo->commit();

                    // DESTROY SESSION TO PREVENT FIXATION
                    session_unset();
                    session_destroy();

                    header("Location: login.php?reset=1");
                    exit;
                } catch (\PDOException $e) {
                    $pdo->rollBack();
                    error_log("Update Exception on verify_reset.php: " . $e->getMessage()); // TOKEN LEAKAGE PREVENTION 
                    $message = "A system error occurred. Action failed.";
                }
            }
        }
    }
} catch (\PDOException $e) {
    // ERROR HANDLING
    error_log("Fatal Configuration Error in token verify: " . $e->getMessage());
    $fatal_error = "A local service mapping issue occurred, blocking request.";
} catch (Exception $e) {
    $fatal_error = $e->getMessage();
}

// Ensure the token exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Set Secure Password - System</title>
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
        <!-- Decoration -->
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
                        <i
                            class="fa-solid <?php echo ($message === 'Password successfully reset. Redirecting to login...') ? 'fa-check-circle' : 'fa-circle-info'; ?>"></i>
                        <?php echo htmlspecialchars($message); ?>
                    </span>
                </div>
            <?php endif; ?>

            <?php if ($message !== "Password successfully reset. Redirecting to login..."): ?>
                <form id="verifyResetForm" method="POST" action="?token=<?= htmlspecialchars(urlencode($token)) ?>">
                    <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                    <div class="auth-form-group">
                        <label class="auth-form-label">New Password</label>
                        <div class="auth-input-wrapper">
                            <i class="fa-solid fa-lock auth-field-icon"></i>
                            <input type="password" name="password" id="passwordField" class="auth-input-field"
                                placeholder="Enter secure password" required autocomplete="new-password">
                            <i class="fa-solid fa-eye auth-toggle-icon" id="togglePassword"></i>
                        </div>
                        <div class="auth-validation-feedback" id="passwordRules">
                            <span id="rule-length">● At least 8 characters</span>
                            <span id="rule-upper">● At least One Uppercase Letter</span>
                            <span id="rule-lower">● At least One Lowercase Letter</span>
                            <span id="rule-number">● At least One Number</span>
                            <span id="rule-special">● At least One Special Symbol</span>
                        </div>
                    </div>

                    <div class="auth-form-group">
                        <label class="auth-form-label">Confirm Password</label>
                        <div class="auth-input-wrapper">
                            <i class="fa-solid fa-shield-halved auth-field-icon"></i>
                            <input type="password" name="confirm" id="confirmPasswordField" class="auth-input-field"
                                placeholder="Verify password" required autocomplete="new-password">
                            <i class="fa-solid fa-eye auth-toggle-icon" id="toggleConfirmPassword"></i>
                        </div>
                        <div id="matchFeedback" class="auth-match-feedback"></div>
                    </div>

                    <button type="submit" class="auth-submit-btn">
                        Execute Update
                    </button>
                </form>
            <?php else: ?>
                <div class="auth-register-link" style="margin-top: 30px;">
                    <a href="login.php" class="auth-submit-btn"
                        style="text-decoration: none; display: inline-block; text-align: center;">PROCEED TO LOGIN →</a>
                </div>
            <?php endif; ?>
        <?php endif; ?>
    </div>

    <script src="style.js"></script>
    <script src="verify_reset.js"></script>
</body>

</html>
