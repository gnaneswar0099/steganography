<?php
// ===== login.php =====
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

// Start session
if (session_status() === PHP_SESSION_NONE) {
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
}

require_once 'db.php';

// Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success_msg = "";
$emailVerificationRequired = app_email_verification_required();

if (isset($_GET['reset']) && $_GET['reset'] === '1') {
    $success_msg = "Password updated successfully. Access system with new credentials.";
}

if (isset($_GET['verified']) && $_GET['verified'] === '1') {
    $success_msg = "Account successfully verified! You may now sign in.";
}

// Redirect if already logged in
if (isset($_SESSION['user_id'])) {
    header("Location: home.php");
    exit;
}

if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // CSRF Check
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        include 'error_session.php';
        exit;
    }

    $email    = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';

    // Basic Validation
    if (empty($email) || empty($password)) {
        $errors[] = "Credentials required.";
    } else {
        $ip = $_SERVER['REMOTE_ADDR'] ?? '0.0.0.0';

        // Rate-limit constants
        $loginMaxAttempts = 10;
        $loginWindowMin   = 15;
        $loginLockoutMsg  = "Too many failed attempts. Access temporarily locked. Please try again later.";

        try {
            // 1. Purge stale records older than window
            $pdo->prepare(
                "DELETE FROM login_attempts
                 WHERE attempt_time < DATE_SUB(NOW(), INTERVAL " . (int)$loginWindowMin . " MINUTE)"
            )->execute();

            // 2.7 Opportunistic 30-day purge
            if (random_int(1, 20) === 1) {
                $pdo->exec("DELETE FROM login_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 30 DAY)");
            }

            // 2. Count recent failures for IP or email
            $stmt = $pdo->prepare(
                "SELECT COUNT(*) FROM login_attempts
                 WHERE (ip_address = ? OR email = ?)
                   AND attempt_time >= DATE_SUB(NOW(), INTERVAL " . (int)$loginWindowMin . " MINUTE)"
            );
            $stmt->execute([$ip, $email]);
            $recentFailures = (int) $stmt->fetchColumn();

            if ($recentFailures >= $loginMaxAttempts) {
                $errors[] = $loginLockoutMsg;
            } else {
                // 3. Look up user
                $stmt = $pdo->prepare(
                    "SELECT id, username, password_hash, email_verified FROM users WHERE email = ?"
                );
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                // Timing attack prevention: dummy verify if user does not exist
                $dummyHash = '$2y$10$dummyHashDummyHashDummyHashDummyHas$';
                $hashToVerify = $user ? $user['password_hash'] : $dummyHash;
                $isValidPass = password_verify($password, $hashToVerify);

                if ($user && $isValidPass) {
                    // C6: Check email verification status
                    if ($emailVerificationRequired && (int)($user['email_verified'] ?? 0) !== 1) {
                        $encodedEmail = urlencode($email);
                        $errors[] = "Your email address has not been verified yet. Please check your inbox or <a href='resend_verification.php?email={$encodedEmail}' style='color:#00ffff;text-decoration:underline;'>request a new activation link</a>.";
                    } else {
                        // SUCCESS
                        $pdo->prepare(
                            "DELETE FROM login_attempts WHERE email = ? OR ip_address = ?"
                        )->execute([$email, $ip]);

                        session_regenerate_id(true); // A9: Prevent session fixation

                        $_SESSION['user_id']       = $user['id'];
                        $_SESSION['username']      = $user['username'];
                        $_SESSION['last_activity'] = time();

                        header("Location: home.php");
                        exit;
                    }
                } else {
                    // FAILURE
                    $pdo->prepare(
                        "INSERT INTO login_attempts (email, ip_address, attempt_time)
                         VALUES (?, ?, NOW())"
                    )->execute([$email, $ip]);

                    $errors[] = "Invalid credentials.";
                }
            }
        } catch (PDOException $e) {
            error_log("Login Error: " . $e->getMessage());
            $errors[] = "Authentication service temporarily unavailable.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Login</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="style.css?v=<?= filemtime('style.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= filemtime('auth.css') ?>">
    <link rel="stylesheet" href="nav.css?v=<?= filemtime('nav.css') ?>">
</head>

<body>
    <div class="grid-container" id="gridContainer"></div>
    <?php
    $isLoggedIn = false;
    $username   = '';
    $activeNav  = 'login';
    ?>
    <?php include 'nav.php'; ?>

    <div class="auth-login-container">
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1>Authentication</h1>
            <p class="auth-status-text">Enter credentials to establish secure session</p>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="auth-error-msg">
                <?php foreach ($errors as $error): ?>
                    <span>
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <?= $error ?>
                    </span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if (!empty($success_msg)): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1);">
                <span>
                    <i class="fa-solid fa-circle-check"></i>
                    <?= htmlspecialchars($success_msg) ?>
                </span>
            </div>
        <?php endif; ?>

        <form method="POST" action="login.php" autocomplete="off">
            <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

            <div class="auth-form-group">
                <label class="auth-form-label">Email</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-envelope auth-field-icon"></i>
                    <input type="email" name="email" class="auth-input-field"
                           placeholder="Enter your email" required
                           value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                           autocomplete="email">
                </div>
            </div>

            <div class="auth-form-group">
                <label class="auth-form-label">Password</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-lock auth-field-icon"></i>
                    <input type="password" name="password" id="passwordField" class="auth-input-field"
                           placeholder="â€¢â€¢â€¢â€¢â€¢â€¢â€¢â€¢" required autocomplete="current-password">
                    <i class="fa-solid fa-eye auth-toggle-icon" id="togglePassword"></i>
                </div>
            </div>

            <div class="auth-remember-row">
                <a href="request_reset.php" class="auth-forgot-link">Forgot password?</a>
            </div>

            <button type="submit" class="auth-submit-btn">
                AUTHENTICATE
            </button>
        </form>

        <div class="auth-register-link">
            Don't have an account? <a href="register.php">Create identity</a>
        </div>
    </div>

    <script src="style.js"></script>
</body>
</html>
