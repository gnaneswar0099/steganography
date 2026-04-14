<?php
/**
 * Beautiful session error page to replace 'die()' messages
 */
header("Content-Security-Policy: default-src 'self'; img-src 'self' data: https:; style-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; font-src 'self' https://cdnjs.cloudflare.com; script-src 'self'");
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Session Interrupt - System</title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css">
    <link rel="stylesheet" href="style.css">
    <link rel="stylesheet" href="auth.css">
</head>
<body>
    <div class="grid-container" id="gridContainer"></div>

    <div class="auth-login-container" style="text-align: center;">
        <div class="corner-decoration top-left"></div>
        <div class="corner-decoration top-right"></div>
        <div class="corner-decoration bottom-left"></div>
        <div class="corner-decoration bottom-right"></div>

        <div class="auth-header">
            <div class="auth-scan-line"></div>
            <h1 style="color: #ff4444; text-shadow: 0 0 20px rgba(255, 68, 68, 0.4);">Session Expired</h1>
            <p class="auth-status-text" style="color: rgba(255, 68, 68, 0.85);">Security Handshake Interrupted</p>
        </div>

        <div class="auth-error-msg" style="margin: 30px 0; padding: 20px; border-color: rgba(255, 68, 68, 0.5); background: rgba(255, 68, 68, 0.05);">
            <p style="font-size: 1.1rem; line-height: 1.5; color: #fff;">
                <i class="fa-solid fa-clock-rotate-left" style="font-size: 2rem; display: block; margin-bottom: 15px; color: #ff4444;"></i>
                Your security session has timed out or was interrupted. To protect your data, the system requires a fresh handshake.
            </p>
        </div>

        <div style="margin-top: 40px;">
            <button onclick="history.back()" class="auth-submit-btn" style="width: auto; padding: 15px 40px; border-color: #00ffff; background: rgba(0, 255, 255, 0.1); margin-right: 15px; font-size: 16px;">
                ← GO BACK
            </button>
            <button onclick="window.location.reload()" class="auth-submit-btn" style="width: auto; padding: 15px 40px; font-size: 16px;">
                REFRESH PAGE <i class="fa-solid fa-rotate"></i>
            </button>
        </div>

        <div class="auth-register-link" style="margin-top: 40px; border-top: 1px solid rgba(0, 255, 255, 0.1); padding-top: 20px;">
            <a href="login.php">RETURN TO MAIN TERMINAL</a>
        </div>
    </div>

    <script src="style.js"></script>
</body>
</html>
