<?php
// ===== register.php =====
declare(strict_types=1);
require_once 'db.php';

// Start Session (Strict)
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

// Generate CSRF Token if not exists
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$errors = [];
$success_msg = "";

// Table creation logic removed to prevent 'CREATE command denied' errors.
// The application assumes the 'users' table already exists.

// Handle Form Submission
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    // 0. CSRF Check
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        include 'error_session.php';
        exit;
    }

    // 1. Sanitization
    $username = trim($_POST['username'] ?? '');
    $email = trim($_POST['email'] ?? '');
    $password = $_POST['password'] ?? '';
    $confirm_password = $_POST['confirm_password'] ?? '';

    // 2. Validation

    // Username: Alphanumeric, 3-50 chars
    if (empty($username)) {
        $errors[] = "Username is required.";
    } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $username)) {
        $errors[] = "Username must be 3-50 characters and alphanumeric.";
    }

    // Email
    if (empty($email)) {
        $errors[] = "Email is required.";
    } elseif (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
        $errors[] = "Invalid email format.";
    }

    // Password Complexity
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

    // Confirm Password
    if ($password !== $confirm_password) {
        $errors[] = "Passwords do not match.";
    }

    // 3. Database Checks (Prepare for Duplicate Entry)
    if (empty($errors)) {
        try {
            // Check existence
            $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
            $stmt->execute([$email]);
            $existing = $stmt->fetch(PDO::FETCH_ASSOC);

            // Compute the password hash regardless of whether the user exists.
            // This prevents attackers from measuring server response times to
            // guess if an email address is already registered. (Timing Attack Mitigation)
            $hashed_password = password_hash($password, PASSWORD_DEFAULT);

            if ($existing) {
                $errors[] = "An account with this email already exists. Please log in or reset your password.";
            } else {
                // 4. Secure Insertion
                $insertStmt = $pdo->prepare("INSERT INTO users (username, email, password_hash) VALUES (?, ?, ?)");
                $insertStmt->execute([$username, $email, $hashed_password]);

                // AUTO LOGIN
                $userId = $pdo->lastInsertId();
                session_regenerate_id(true);
                $_SESSION['user_id'] = $userId;
                $_SESSION['username'] = $username;
                $_SESSION['last_activity'] = time();

                $success_msg = "Registration successful. Initializing session...";
                // Redirect on success
                header("Location: home.php");
                exit;
            }
        } catch (PDOException $e) {
            // Log real error, show generic
            error_log("Registration Error: " . $e->getMessage());
            $errors[] = "A system error occurred during registration.";
        }
    }
}
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Register</title>
    <!-- CSS Dependencies -->
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="style.css?v=<?= filemtime('style.css') ?>">
    <link rel="stylesheet" href="auth.css?v=<?= filemtime('auth.css') ?>">
    <link rel="stylesheet" href="nav.css?v=<?= filemtime('nav.css') ?>">
</head>

<body>
    <!-- Background Effects -->
    <div class="grid-container" id="gridContainer"></div>
    <?php
    $isLoggedIn = false;
    $username   = '';
    $activeNav  = 'register';
    ?>
    <?php include 'nav.php'; ?>

    <div class="auth-login-container">
        <!-- Corner Decorations -->
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <!-- Header -->
        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1>REGISTER</h1>
            <p class="auth-status-text">New User Detected</p>
        </div>

        <!-- Feedback Messages -->
        <?php if (!empty($errors)): ?>
            <div class="auth-error-msg">
                <?php foreach ($errors as $error): ?>

                    <div class="auth-err-item"><i class="fa-solid fa-triangle-exclamation"></i>
                        <?php echo htmlspecialchars($error); ?></div>
                <?php endforeach; ?>
            </div>
        <?php endif; ?>

        <?php if ($success_msg): ?>
            <div class="auth-success-msg">
                <p><i class="fa-solid fa-check-circle"></i> <?php echo htmlspecialchars($success_msg); ?></p>
            </div>
        <?php endif; ?>

        <!-- Registration Form -->

        <form id="registerFormPHP" action="<?php echo htmlspecialchars($_SERVER['PHP_SELF']); ?>" method="POST">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            <!-- Turn off autocomplete for security -->
            <input type="hidden" name="action" value="register">

            <div class="auth-form-group">
                <label class="auth-form-label">Username</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-user-astronaut auth-field-icon"></i>
                    <input type="text" name="username" class="auth-input-field" placeholder="Alphanumeric ID"
                        value="<?php echo isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>"
                        required autocomplete="off">
                </div>
            </div>

            <div class="auth-form-group">
                <label class="auth-form-label">Email</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-envelope auth-field-icon"></i>
                    <input type="email" name="email" class="auth-input-field" placeholder="Secure email address"
                        value="<?php echo isset($_POST['email']) ? htmlspecialchars($_POST['email']) : ''; ?>" required
                        autocomplete="email">
                </div>
            </div>

            <div class="auth-form-group">
                <label class="auth-form-label">Create Password</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-lock auth-field-icon"></i>
                    <input type="password" name="password" id="passwordField" class="auth-input-field"
                        placeholder="Create password" required autocomplete="new-password">
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
                    <input type="password" name="confirm_password" id="confirmPasswordField" class="auth-input-field"
                        placeholder="Confirm password" required autocomplete="new-password">
                    <i class="fa-solid fa-eye auth-toggle-icon" id="toggleConfirmPassword"></i>
                </div>
                <div id="matchFeedback" class="auth-match-feedback"></div>
            </div>
            <button type="submit" class="auth-submit-btn" id="submitBtn">
                Register
            </button>
        </form>

        <div class="auth-divider">
            <span class="auth-divider-text">ALREADY HAVE CLEARANCE?</span>
        </div>

        <div class="auth-register-link">
            <a href="login.php">RETURN TO LOGIN →</a>
        </div>
    </div>

    <!-- Scripts -->
    <script src="style.js"></script>
    <script>
        const passwordInput = document.getElementById('passwordField');
        const confirmInput = document.getElementById('confirmPasswordField');
        const matchFeedback = document.getElementById('matchFeedback');
        const passwordRules = document.getElementById('passwordRules');
        const submitBtn = document.getElementById('submitBtn');

        const rules = {
            length:  { el: document.getElementById('rule-length'),  regex: /.{8,}/,   label: 'At least 8 characters' },
            upper:   { el: document.getElementById('rule-upper'),   regex: /[A-Z]/,   label: 'At least One Uppercase Letter' },
            lower:   { el: document.getElementById('rule-lower'),   regex: /[a-z]/,   label: 'At least One Lowercase Letter' },
            number:  { el: document.getElementById('rule-number'),  regex: /[0-9]/,   label: 'At least One Number' },
            special: { el: document.getElementById('rule-special'), regex: /[\W_]/,   label: 'At least One Special Symbol' }
        };

        // Show validation on focus
        passwordInput.addEventListener('focus', () => {
            passwordRules.style.display = 'flex';
        });

        // Hide validation on blur
        passwordInput.addEventListener('blur', () => {
            passwordRules.style.display = 'none';
        });

        function validatePassword() {
            const val = passwordInput.value;

            // Auto-show if typing happens
            if (val.length > 0) passwordRules.style.display = 'flex';

            let allValid = true;

            for (const key in rules) {
                const rule = rules[key];
                if (rule.regex.test(val)) {
                    rule.el.classList.remove('auth-invalid-rule');
                    rule.el.classList.add('auth-valid-rule');
                    rule.el.innerHTML = '<i class="fa-solid fa-check"></i> ' + rule.label;
                } else {
                    rule.el.classList.remove('auth-valid-rule');
                    rule.el.classList.add('auth-invalid-rule');
                    rule.el.innerHTML = '● ' + rule.label;
                    allValid = false;
                }
            }

            validateMatch();
            return allValid;
        }

        function validateMatch() {
            const pass = passwordInput.value;
            const confirm = confirmInput.value;

            if (!confirm) {
                matchFeedback.textContent = '';
                return false;
            }

            if (pass === confirm) {
                matchFeedback.textContent = 'Passwords Match';
                matchFeedback.style.color = '#00ff88';
                return true;
            } else {
                matchFeedback.textContent = 'Passwords Do Not Match';
                matchFeedback.style.color = '#ff4444';
                return false;
            }
        }

        passwordInput.addEventListener('input', validatePassword);
        confirmInput.addEventListener('input', validateMatch);

        // Block submit if password requirements not met
        document.getElementById('registerFormPHP').addEventListener('submit', function (e) {
            if (!this.checkValidity()) {
                return;
            }
            const isPassValid = validatePassword();
            const isMatchValid = validateMatch();

            if (!isPassValid || !isMatchValid) {
                e.preventDefault();
                // Show inline error instead of alert()
                let inlineErr = document.getElementById('js-inline-error');
                if (!inlineErr) {
                    inlineErr = document.createElement('div');
                    inlineErr.id = 'js-inline-error';
                    inlineErr.className = 'auth-error-msg';
                    inlineErr.style.marginBottom = '8px';
                    this.insertBefore(inlineErr, this.firstChild);
                }
                if (!isPassValid) {
                    inlineErr.innerHTML = '<span><i class="fa-solid fa-triangle-exclamation"></i> Please ensure all password requirements are met.</span>';
                } else {
                    inlineErr.innerHTML = '<span><i class="fa-solid fa-triangle-exclamation"></i> Passwords do not match.</span>';
                }
                inlineErr.scrollIntoView({ behavior: 'smooth', block: 'center' });
            } else {
                e.preventDefault(); // Stop immediate submission to play animation
                document.getElementById('processingOverlay').classList.add('visible');
                document.body.style.overflow = 'hidden';
                if (submitBtn) submitBtn.disabled = true;

                // Submit immediately
                this.submit();
            }
        });
    </script>
</body>

</html>
