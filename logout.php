<?php
// ===== logout.php =====
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

if (session_status() === PHP_SESSION_NONE) {
    app_start_session();
}

// A8: Logout is strictly POST with CSRF validation
if ($_SERVER['REQUEST_METHOD'] !== 'POST') {
    http_response_code(405);
    header('Allow: POST');
    exit('This action is not available for this request.');
}

$sessionToken = $_SESSION['csrf_token'] ?? '';
$postToken    = $_POST['csrf_token'] ?? '';

if (empty($sessionToken) || empty($postToken) || !hash_equals($sessionToken, $postToken)) {
    http_response_code(403);
    exit('Your session expired or the page was open too long. Please reload the page and try again.');
}

app_destroy_session();

header("Location: home.php");
exit;