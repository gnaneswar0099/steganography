<?php
// ===== db.php =====
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

// BLOCK DIRECT ACCESS
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}
/*
|--------------------------------------------------------------------------
| Database Configuration
|--------------------------------------------------------------------------
| NOTE:
| - Uses least-privilege user (NOT root)
| - MySQL runs as standalone service (MySQL80)
| - Port is explicitly defined to avoid ambiguity
*/
/*
|--------------------------------------------------------------------------
| Load .env for sensitive credentials
|--------------------------------------------------------------------------
| DB_PASS is read from the .env file (web-blocked via .htaccess).
*/
$_env = file_exists(__DIR__ . '/.env') ? (parse_ini_file(__DIR__ . '/.env') ?: []) : [];

$db_host    = app_env('DB_HOST', $_env, 'localhost');
$db_port    = app_env('DB_PORT', $_env, '3306');
$db_name    = app_env('DB_NAME', $_env, 'steganography');
$db_user    = app_env('DB_USER', $_env, 'steg_user');
$db_pass    = app_env('DB_PASS', $_env, '');
$db_charset = "utf8mb4";

unset($_env); // Don't leave credentials in scope

/*
|--------------------------------------------------------------------------
| PDO Options (SECURITY-CRITICAL)
|--------------------------------------------------------------------------
*/
$options = [
    PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES => false,
    PDO::ATTR_STRINGIFY_FETCHES => false,
];

if (str_ends_with(strtolower($db_host), '.mysql.database.azure.com')) {
    $sslCaCandidates = array_filter([
        app_env('MYSQL_SSL_CA', $_env ?? null),
        '/etc/ssl/certs/ca-certificates.crt',
        '/etc/pki/tls/certs/ca-bundle.crt',
        'C:\\xampp\\apache\\bin\\curl-ca-bundle.crt',
        'C:\\xampp\\php\\extras\\ssl\\cacert.pem',
    ]);

    foreach ($sslCaCandidates as $sslCaPath) {
        if (is_string($sslCaPath) && file_exists($sslCaPath)) {
            $options[PDO::MYSQL_ATTR_SSL_CA] = $sslCaPath;
            break;
        }
    }
}

/*
|--------------------------------------------------------------------------
| Create Connection
|--------------------------------------------------------------------------
*/
try {
    $dsn = "mysql:host={$db_host};port={$db_port};dbname={$db_name};charset={$db_charset}";
    $pdo = new PDO($dsn, $db_user, $db_pass, $options);
} catch (PDOException $e) {
    // Log real error (server-side only)
    error_log("Database connection error: " . $e->getMessage());

    // Generic message for users (no info leakage)
    http_response_code(503);
    die("Service temporarily unavailable.");
}
