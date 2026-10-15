<?php
// ===== register.php =====
declare(strict_types=1);
require_once __DIR__ . '/app_config.php';

header('Content-Type: text/html; charset=UTF-8');
require_once 'db.php';
require_once 'mailer.php';

// Start Session (Strict)
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

// Generate CSRF Token
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$registered_success = false;
$success_msg = "";
$emailVerificationRequired = app_email_verification_required();

// Handle Form Submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // CSRF Check
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        include 'error_session.php';
        exit;
    }

    $username         = trim($_POST['username'] ?? '');
    $email            = trim($_POST['email'] ?? '');
    $password         = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // Validation
    if (empty($username)) {
        $errors[] = "Username is required.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
        $errors[] = "Username must be 3-50 characters and alphanumeric.";
    }

    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (strlen($email) > 255 || !filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    if (empty($password)) {
        $errors[] = "Password is required.";
    } else {
        if (strlen($password) < 8) {
            $errors[] = "Password must be at least 8 characters.";
        }
        if (!preg_match('/[A-Z]/', $password)) {
            $errors[] = "Password must contain at least one uppercase letter.";
        }
        if (!preg_match('/[a-z]/', $password)) {
            $errors[] = "Password must contain at least one lowercase letter.";
        }
        if (!preg_match('/[0-9]/', $password)) {
            $errors[] = "Password must contain at least one number.";
        }
        if (!preg_match('/[\W_]/', $password)) {
            $errors[] = "Password must contain at least one special symbol.";
        }
    }

    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    if (empty($errors)) {
        try {
            // Timing attack mitigation: always compute hash
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            // Check existence
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            if ($existing) {
                $errors[] = "An account with this email already exists. Please log in or reset your password.";
            } else {
                $token = $emailVerificationRequired ? bin2hex(random_bytes(32)) : '';
                $tokenHash = $emailVerificationRequired ? hash('sha256', $token) : '';
                $emailVerified = $emailVerificationRequired ? 0 : 1;

                $pdo->beginTransaction();

                $insertStmt = $pdo->prepare(
                    "INSERT INTO users (username, email, password_hash, email_verified) VALUES (?, ?, ?, ?)"
                );
                $insertStmt->execute([$username, $email, $hashed_password, $emailVerified]);

                if ($emailVerificationRequired) {
                    $pdo->prepare("DELETE FROM email_verifications WHERE email = ?")->execute([$email]);
                    $verifyStmt = $pdo->prepare(
                        "INSERT INTO email_verifications (email, token_hash, expires_at)
                         VALUES (?, ?, NOW() + INTERVAL 24 HOUR)"
                    );
                    $verifyStmt->execute([$email, $tokenHash]);
                }

                $pdo->commit();

                if ($emailVerificationRequired) {
                    $activationLink = null;
                    try {
                        $base_dir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
                        $activationLink = app_public_origin() . $base_dir . "/verify_email.php?token=" . urlencode($token);
                    } catch (RuntimeException $e) {
                        error_log("Link build failed: invalid or missing APP_URL");
                    }

                    if ($activationLink !== null) {
                        $subject  = "Activate your Steganography Account";
                        $htmlBody = "Hello " . htmlspecialchars($username, ENT_QUOTES, 'UTF-8') . ",<br><br>"
                                  . "Thank you for creating an account. Please click the button or link below to verify your email and activate your account:<br><br>"
                                  . "<a href='" . htmlspecialchars($activationLink, ENT_QUOTES, 'UTF-8') . "' style='display:inline-block;padding:10px 20px;background:#00ffff;color:#000;font-weight:bold;text-decoration:none;border-radius:4px;'>ACTIVATE ACCOUNT</a><br><br>"
                                  . "Or copy and paste this link into your browser:<br>"
                                  . htmlspecialchars($activationLink, ENT_QUOTES, 'UTF-8') . "<br><br>"
                                  . "This link will expire in 24 hours.<br><br>"
                                  . "If you did not sign up for this account, please ignore this email.";

                        $textBody = "Hello {$username},\n\n"
                                  . "Thank you for creating an account. Please visit the link below to verify your email:\n\n"
                                  . "{$activationLink}\n\n"
                                  . "This link will expire in 24 hours.\n\n"
                                  . "If you did not sign up, please ignore this message.";

                        send_system_email($email, $subject, $htmlBody, $textBody);
                    }

                    $success_msg = "Registration successful! A verification link has been dispatched to your email address. Please click the link to activate your account before logging in.";
                } else {
                    $success_msg = "Registration successful! You may now sign in.";
                }

                $registered_success = true;
            }
        } catch (PDOException $e) {
            if ($pdo->inTransaction()) {
                $pdo->rollBack();
            }
            if ($e->getCode() === '23000') {
                $errors[] = "An account with this email already exists.";
            } else {
                error_log("Registration Error: " . $e->getMessage());
                $errors[] = "A system error occurred during registration.";
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Create Account | Steganography</title>
    <meta name="description" content="Create a secure Steganography account.">
    <link rel="icon" href="/favicon.svg" type="image/svg+xml">
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
    $activeNav  = 'register';
    ?>
    <?php include 'nav.php'; ?>

    <div class="auth-login-container">
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1>Create Identity</h1>
            <p class="auth-status-text">Initialize new secure user</p>
        </div>

        <?php if (!empty($errors)): ?>
            <div class="auth-error-msg" role="alert">
                <?php foreach ($errors as $error): ?>
                    <span>
                        <i class="fa-solid fa-triangle-exclamation"></i>
                        <?= htmlspecialchars($error) ?>
                    </span>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($registered_success): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1); margin-bottom: 25px;">
                <span>
                    <i class="fa-solid fa-envelope-circle-check"></i>
                    <?= htmlspecialchars($success_msg) ?>
                </span>
            </div>
            <div style="text-align: center; margin-top: 25px;">
                <a href="login.php" class="auth-submit-btn" style="text-decoration: none; display: inline-block;">
                    PROCEED TO LOGIN &nbsp;<i class="fa-solid fa-arrow-right"></i>
                </a>
            </div>
            <?php if ($emailVerificationRequired): ?>
                <div class="auth-register-link" style="margin-top: 20px;">
                    Didn't get the email? <a href="resend_verification.php?email=<?= urlencode($email) ?>">Resend link</a>
                </div>
            <?php endif; ?>
        <?php else: ?>
            <form id="registerForm" method="POST" action="register.php" autocomplete="on">
                <input type="hidden" name="csrf_token" value="<?= htmlspecialchars($_SESSION['csrf_token']) ?>">

                <div class="auth-form-group">
                    <label class="auth-form-label" for="usernameField">Username</label>
                    <div class="auth-input-wrapper">
                        <i class="fa-solid fa-user auth-field-icon"></i>
                        <input type="text" name="username" id="usernameField" class="auth-input-field"
                            placeholder="Alphanumeric, 3-50 chars" required
                            value="<?= htmlspecialchars($_POST['username'] ?? '') ?>"
                            autocomplete="username" maxlength="50">
                    </div>
                </div>

                <div class="auth-form-group">
                    <label class="auth-form-label" for="emailField">Email</label>
                    <div class="auth-input-wrapper">
                        <i class="fa-solid fa-envelope auth-field-icon"></i>
                        <input type="email" name="email" id="emailField" class="auth-input-field"
                            placeholder="user@domain.com" required
                            value="<?= htmlspecialchars($_POST['email'] ?? '') ?>"
                            autocomplete="email" maxlength="255">
                    </div>
                </div>

                <div class="auth-form-group">
                    <label class="auth-form-label" for="passwordField">Password</label>
                    <div class="auth-input-wrapper">
                        <i class="fa-solid fa-lock auth-field-icon"></i>
                        <input type="password" name="password" id="passwordField" class="auth-input-field"
                            placeholder="Create a password" required autocomplete="new-password">
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
                        <input type="password" name="confirm_password" id="confirmPasswordField" class="auth-input-field"
                            placeholder="Confirm your password" required autocomplete="new-password">
                        <button type="button" class="auth-toggle-icon" id="toggleConfirmPassword" aria-label="Show password" aria-controls="confirmPasswordField" aria-pressed="false"><i class="fa-solid fa-eye" aria-hidden="true"></i></button>
                    </div>
                    <div id="matchFeedback" class="auth-match-feedback"></div>
                </div>

                <button type="submit" class="auth-submit-btn">
                    REGISTER IDENTITY
                </button>
            </form>

            <div class="auth-register-link">
                Already registered? <a href="login.php">Authenticate</a>
            </div>
        <?php endif; ?>
    </div>

    <script src="style.js"></script>
    <script src="verify_reset.js"></script>
</body>
</html>
