<?php
// ===== ip_debug.php =====
// Diagnostic endpoint to verify reverse proxy IP forwarding and HTTPS detection on Render.
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

$_env = file_exists(__DIR__ . '/.env') ? (parse_ini_file(__DIR__ . '/.env') ?: []) : [];
$expectedToken = app_env('IP_DEBUG_TOKEN', $_env, '');

// A5: Disabled unless IP_DEBUG_TOKEN is configured and matches via hash_equals
$providedToken = (string) ($_GET['token'] ?? '');
if (empty($expectedToken) || !hash_equals($expectedToken, $providedToken)) {
    http_response_code(404);
    exit;
}

header('Content-Type: application/json; charset=UTF-8');
header('X-Robots-Tag: noindex, nofollow');

echo json_encode([
    'status'              => 'ok',
    'remote_addr'         => $_SERVER['REMOTE_ADDR'] ?? null,
    'x_forwarded_for'     => $_SERVER['HTTP_X_FORWARDED_FOR'] ?? null,
    'x_forwarded_proto'   => $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? null,
    'https_server_var'    => $_SERVER['HTTPS'] ?? null,
    'server_port'         => $_SERVER['SERVER_PORT'] ?? null,
    'app_is_https'        => app_is_https(),
    'php_version'         => PHP_VERSION,
    'current_utc_time'    => gmdate('Y-m-d H:i:s'),
], JSON_PRETTY_PRINT);