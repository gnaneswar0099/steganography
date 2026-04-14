<?php
declare(strict_types=1);

// 8. SECURITY HEADERS
header("Referrer-Policy: no-referrer");
header("X-Frame-Options: DENY");
header("X-Content-Type-Options: nosniff");
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self'");

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception;

// 9. SESSION TIMEOUT EXTENSION (2 Hours)
ini_set('session.gc_maxlifetime', '7200');
$isSecure = isset($_SERVER['HTTPS']) && $_SERVER['HTTPS'] === 'on';
session_set_cookie_params([
    'lifetime' => 7200, // 2 hours instead of transient
    'path' => '/',
    'domain' => '',
    'secure' => $isSecure,
    'httponly' => true,
    'samesite' => 'Strict'
]);
session_start();

// Load dependencies (using composer autoloader for PHPMailer if present)
if (file_exists(__DIR__ . '/vendor/autoload.php')) {
    require __DIR__ . '/vendor/autoload.php';
}

// Ensure db.php is required for $pdo instance
require_once __DIR__ . '/db.php';

// 1. HTTPS ENFORCEMENT WITH LOCALHOST EXCEPTION
$isLocalhost = in_array($_SERVER['REMOTE_ADDR'], ['127.0.0.1', '::1']) || str_contains($_SERVER['HTTP_HOST'], 'localhost') || str_contains($_SERVER['HTTP_HOST'], '127.0.0.1');
if (!$isSecure && !$isLocalhost) {
    $redirect_url = "https://" . $_SERVER['HTTP_HOST'] . $_SERVER['REQUEST_URI'];
    header("Location: $redirect_url", true, 301);
    exit();
}

// ANTI-ENUMERATION PROTECTION
$generic_message = "If the email exists, a password reset link has been sent.";
$message = '';

// 1. CSRF TOKEN — generated BEFORE the POST block so the token always
//    exists in the session at the time the CSRF check runs.
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    // 13. CSRF PROTECTION
    $sessionToken = $_SESSION['csrf_token'] ?? '';
    $postToken = $_POST['csrf_token'] ?? '';
    
    if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
        include 'error_session.php';
        exit;
    }
    
    // We no longer regenerate on every POST to prevent errors with back/forward navigation
    // The token remains valid for the session duration.

    $email = trim($_POST['email'] ?? '');

    if (strlen($email) > 255) {
        $email = '';
    }

    // 10. EMAIL INPUT VALIDATION (Length and Format)
    if (strlen($email) <= 255 && filter_var($email, FILTER_VALIDATE_EMAIL)) {
        try {
            // 3. EXPIRED TOKEN CLEANUP (Prevent database growth)
            $pdo->exec("DELETE FROM password_resets WHERE expires_at < NOW()");

            // 4. RATE-LIMIT TABLE CLEANUP (Remove old attempt records > 24 hours)
            $pdo->exec("DELETE FROM password_reset_attempts WHERE attempt_time < DATE_SUB(NOW(), INTERVAL 24 HOUR)");

            // 5. MAINTAIN RATE LIMITING (Max 3 queries per hour per email address)
            $stmt = $pdo->prepare("
                SELECT COUNT(*) 
                FROM password_reset_attempts 
                WHERE email = ? AND attempt_time > DATE_SUB(NOW(), INTERVAL 1 HOUR)
            ");
            $stmt->execute([$email]);
            $attempts = (int)$stmt->fetchColumn();

            if ((int)$attempts < 3) {
                // Log the attempt with IP for the new table structure
                $ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
                $stmt = $pdo->prepare("INSERT INTO password_reset_attempts (email, attempt_time, ip_address) VALUES (?, NOW(), ?)");
                $stmt->execute([$email, $ip]);

                // 13. PREPARED STATEMENTS (SQL Injection prevention)
                $stmt = $pdo->prepare("SELECT id FROM users WHERE email = ?");
                $stmt->execute([$email]);
                
                if ($stmt->fetch()) {
                    // 11. SECURE TOKEN GENERATION
                    $token = bin2hex(random_bytes(32));
                    
                    // 11. TOKEN STORAGE SECURITY (Hashing)
                    $token_hash = hash('sha256', $token);
                    
                    // 11. CAPTURE REQUEST METADATA FOR AUDIT / ANOMALY LOGGING
                    $capture_ip = $_SERVER['REMOTE_ADDR'] ?? 'UNKNOWN';
                    $capture_ua = substr($_SERVER['HTTP_USER_AGENT'] ?? 'UNKNOWN', 0, 255);

                    // 11. CLEAR PREVIOUS TOKENS FOR EMAIL
                    $stmt = $pdo->prepare("DELETE FROM password_resets WHERE email = ?");
                    $stmt->execute([$email]);
                    
                    // INSERT NEW TOKEN (Matching the updated table structure)
                    $stmt = $pdo->prepare("
                        INSERT INTO password_resets (email, token_hash, expires_at, request_ip, user_agent) 
                        VALUES (?, ?, NOW() + INTERVAL 30 MINUTE, ?, ?)
                    ");
                    $stmt->execute([$email, $token_hash, $capture_ip, $capture_ua]);
                    
                    // 6. IMPROVE RESET LINK CONSTRUCTION (Dynamic paths for subfolders)
                    $protocol = $isSecure ? "https" : "http";
                    $base_dir = rtrim(dirname($_SERVER['SCRIPT_NAME']), '/\\');
                    $reset_link = $protocol . "://" . $_SERVER['HTTP_HOST'] . $base_dir . "/verify_reset.php?token=" . urlencode($token);
                    
                    // 13. PHPMAILER EMAIL SENDING
                    if (class_exists(PHPMailer::class)) {
                        
                        // Fallback parser if getenv() is empty natively due to missing phpdotenv library loaders
                        $envPath = __DIR__ . '/.env';
                        $env = file_exists($envPath) ? parse_ini_file($envPath) : [];
                        
                        $smtpHost = $env['SMTP_HOST'] ?? getenv('SMTP_HOST') ?: 'smtp.gmail.com';
                        $smtpUser = $env['SMTP_USER'] ?? getenv('SMTP_USER') ?: '';
                        $smtpPass = $env['SMTP_PASS'] ?? getenv('SMTP_PASS') ?: '';
                        $smtpPort = (int)($env['SMTP_PORT'] ?? getenv('SMTP_PORT') ?: 587);

                        $mail = new PHPMailer(true);
                        
                        // DEVELOPMENT ONLY: Enable debug tracking
                        // $mail->SMTPDebug = \PHPMailer\PHPMailer\SMTP::DEBUG_SERVER;
                        // $mail->Debugoutput = 'html';

                        $mail->isSMTP();
                        $mail->Host       = $smtpHost;
                        $mail->SMTPAuth   = true;              
                        $mail->Username   = $smtpUser;       
                        $mail->Password   = $smtpPass;       
                        $mail->SMTPSecure = PHPMailer::ENCRYPTION_STARTTLS; 
                        $mail->Port       = $smtpPort;               
                        
                        $mail->setFrom($smtpUser ?: 'security@localhost', 'Security Team');
                        $mail->addAddress($email);
                        $mail->isHTML(true);
                        
                        // 7. IMPROVE EMAIL MESSAGE
                        $mail->Subject = 'Secure Password Reset';
                        $mail->Body    = "A password reset request was received for your account.<br>
                                          If you initiated this request, click the link below to reset your password:<br><br>
                                          <a href='{$reset_link}'>Reset Password</a><br><br>
                                          This link will expire in 30 minutes.";

                        $mail->AltBody = "A password reset request was received for your account.\n"
                                       . "If you initiated this request, copy and paste the link below to reset your password:\n\n"
                                       . "{$reset_link}\n\n"
                                       . "This link will expire in 30 minutes.";

                        try {
                            $mail->send();
                        } catch (Exception $e) {
                            error_log("Mailer Error: " . $e->getMessage()); 
                        }
                    }
                }
            }
        } catch (PDOException $e) {
            error_log("DB Error in request_reset: " . $e->getMessage());
        }
    }
    // Maintain anti-enumeration protection — always show the same generic message.
    $message = $generic_message;
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Reset Password - System</title>
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
            <h1>Password Reset</h1>
            <p class="auth-status-text">Account Recovery Module</p>
        </div>

        <?php if ($message): ?>
            <div class="auth-error-msg" style="color: #00ffcc; border-color: #00ffcc; background: rgba(0, 255, 204, 0.1);">
                <span><i class="fa-solid fa-circle-info"></i> <?php echo htmlspecialchars($message); ?></span>
            </div>
        <?php endif; ?>

        <form id="resetRequestForm" method="POST" action="">
            <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
            
            <div class="auth-form-group">
                <label class="auth-form-label">Registered Email</label>
                <div class="auth-input-wrapper">
                    <i class="fa-solid fa-envelope auth-field-icon"></i>
                    <input type="email" name="email" class="auth-input-field" placeholder="Enter email address" required autocomplete="email" maxlength="255">
                </div>
            </div>

            <button type="submit" class="auth-submit-btn">
                Transmit Request
            </button>
        </form>

        <div class="auth-register-link">
            <a href="login.php">← RETURN TO LOGIN</a>
        </div>
    </div>

    <script src="style.js"></script>
    <script src="request_reset.js"></script>
</body>
</html>
