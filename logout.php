<?php
// ===== logout.php =====
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

if (session_status() === PHP_SESSION_NONE) {
    session_start();
}

// A8: Logout is strictly POST with CSRF validation
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('Method Not Allowed: Logout requires POST.');
}

$sessionToken = $_SESSION['csrf_token'] ?? '';
$postToken    = $_POST['csrf_token'] ?? '';

if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
    http_response_code(403);
    exit('Invalid CSRF token.');
}

// Unset all session variables
$_SESSION = [];

// Destroy session cookie
if (ini_get("session.use_cookies")) {
    $params = session_get_cookie_params();
    setcookie(
        session_name(),
        '',
        time() - 3600,
        $params["path"],
        $params["domain"],
        $params["secure"],
        $params["httponly"]
    );
}

session_destroy();

header("Location: home.php");
exit;