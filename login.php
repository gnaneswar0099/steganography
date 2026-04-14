<?php
// ===== login.php =====
declare(strict_types=1);

// Start session
if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.gc_maxlifetime', '7200');
    $isSecure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
    session_set_cookie_params([
        'lifetime' => 7200,
        'path' => '/',
        'domain' => '',
        'secure' => $isSecure,
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

if (isset($_GET['reset']) && $_GET['reset'] === '1') {
    $success_msg = "Password updated successfully. Access system with new credentials.";
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

        // ── Rate-limit constants ───────────────────────────────────────────
        $loginMaxAttempts = 10;   // max failures allowed
        $loginWindowMin   = 15;   // sliding window in minutes
        $loginLockoutMsg  = "Too many failed attempts. Access temporarily locked. Please try again later.";

        try {
            // ── 1. Purge stale records (older than the window) ─────────────
            // The value is an integer constant so concatenation is safe here.
            $pdo->prepare(
                "DELETE FROM login_attempts
                 WHERE attempt_time < DATE_SUB(NOW(), INTERVAL " . (int)$loginWindowMin . " MINUTE)"
            )->execute();

            // ── 2. Count recent failures for this IP OR email ──────────────
            $stmt = $pdo->prepare(
                "SELECT COUNT(*) FROM login_attempts
                 WHERE (ip_address = ? OR email = ?)
                   AND attempt_time >= DATE_SUB(NOW(), INTERVAL " . (int)$loginWindowMin . " MINUTE)"
            );
            $stmt->execute([$ip, $email]);
            $recentFailures = (int) $stmt->fetchColumn();

            if ($recentFailures >= $loginMaxAttempts) {
                // ── LOCKED ─────────────────────────────────────────────────
                $errors[] = $loginLockoutMsg;

            } else {
                // ── 3. Look up user and verify password ────────────────────
                $stmt = $pdo->prepare(
                    "SELECT id, username, password_hash FROM users WHERE email = ?"
                );
                $stmt->execute([$email]);
                $user = $stmt->fetch();

                // Prevent user enumeration timing attacks by always computing the hash
                $dummyHash = '$2y$10$dummyHashDummyHashDummyHashDummyHas$';
                $hashToVerify = $user ? $user['password_hash'] : $dummyHash;
                $isValidPass = password_verify($password, $hashToVerify);

                if ($user && $isValidPass) {
                    // ── SUCCESS ────────────────────────────────────────────
                    // Clear stored failures for this email and current IP so a
                    // legitimate user is not kept locked out by stale records.
                    $pdo->prepare(
                        "DELETE FROM login_attempts WHERE email = ? OR ip_address = ?"
                    )->execute([$email, $ip]);

                    session_regenerate_id(true); // Prevent session fixation

                    $_SESSION['user_id']       = $user['id'];
                    $_SESSION['username']      = $user['username'];
                    $_SESSION['last_activity'] = time();

                    header("Location: home.php");
                    exit;

                } else {
                    // ── FAILURE — log attempt then show generic error ───────
                    $pdo->prepare(
                        "INSERT INTO login_attempts (email, ip_address, attempt_time)
                         VALUES (?, ?, NOW())"
                    )->execute([$email, $ip]);

                    // How many attempts remain before lockout?
                    $remaining = $loginMaxAttempts - ($recentFailures + 1);

                    if ($remaining <= 0) {
                        $errors[] = $loginLockoutMsg;
                    } elseif ($remaining <= 3) {
                        // Warn when getting close so the user knows
                        $errors[] = "Invalid access credentials. Warning: {$remaining} attempt(s) remaining before temporary lockout.";
                    } else {
                        $errors[] = "Invalid access credentials.";
                    }

                    sleep(1); // Secondary delay — still costs 1 s per non-locked attempt
                }
            }

        } catch (PDOException $e) {
            error_log("Login Error: " . $e->getMessage());
            $errors[] = "System authentication error.";
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
    <?php
    $isLoggedIn = false;
    $username   = '';
    $activeNav  = 'login';
    ?>
    <div class="grid-container" id="gridContainer"></div>
    <?php include 'nav.php'; ?>


    <div class="auth-login-container">
        <!-- Decoration -->
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1>LOGIN</h1>
            <p class="auth-status-text">System Ready</p>
        </div>

        <?php if (!empty($success_msg)): ?>
            <div class="auth-success-msg">
                <span><i class="fa-solid fa-circle-check"></i> <?php echo htmlspecialchars($success_msg); ?></span>
            </div>
        <?php endif; ?>

        <?php if (!empty($errors)): ?>
            <div class="auth-error-msg">
                <?php foreach ($errors as $error): ?>
                    <span><i class="fa-solid fa-triangle-exclamation"></i> <?php echo htmlspecialchars($error); ?></span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <form id="loginFormPHP" action="<?php echo htmlspecialchars($_SERVER["PHP_SELF"]); ?>" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <div class="auth-form-group">
                <label class="auth-form-label">User Identification</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-user auth-field-icon"></i>
                    <input type="email" name="email" class="auth-input-field" placeholder="Enter email address"
                        value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required
                        autocomplete="email">
                </div>
            </div>

            <div class="auth-form-group">
                <label class="auth-form-label">Password</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-lock auth-field-icon"></i>
                    <input type="password" name="password" id="passwordField" class="auth-input-field"
                        placeholder="Enter password" required autocomplete="current-password">
                    <i class="fa-solid fa-eye auth-toggle-icon" id="togglePassword"></i>
                </div>
            </div>

            <div class="auth-checkbox-group" style="justify-content: flex-end;">
                <a href="request_reset.php" class="auth-forgot-link">Forgot Password?</a>
            </div>

            <button type="submit" class="auth-submit-btn">
                Initialize Login
            </button>
        </form>

        <div class="auth-register-link">
            <a href="register.php">CREATE NEW ACCOUNT →</a>
        </div>

    </div>

    <script src="style.js"></script>
    <script>
        document.getElementById('loginFormPHP').addEventListener('submit', function (e) {
            if (!this.checkValidity()) {
                return;
            }
            e.preventDefault(); // Stop immediate submission to play animation
            document.getElementById('processingOverlay').classList.add('visible');
            document.body.style.overflow = 'hidden';

            const btn = this.querySelector('button[type="submit"]');
            if (btn) btn.disabled = true;

            // Submit immediately
            this.submit();
        });
    </script>
</body>

</html>
