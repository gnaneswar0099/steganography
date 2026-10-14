<?php
// ===== db.php =====
declare(strict_types=1);

// Prevent direct access
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}

require_once __DIR__ . '/app_config.php';

// Force UTC timezone for consistency across PHP and MySQL
date_default_timezone_set('UTC');

/*
|--------------------------------------------------------------------------
| Database Configuration
|--------------------------------------------------------------------------
| Credentials come exclusively from environment variables (set in the
| container or via a .env file for local development).
| DB_NAME is case-sensitive: "Steganography" (required by Aiven).
| Aiven requires an SSL CA certificate; ca.pem must sit next to db.php.
*/
$_env = file_exists(__DIR__ . '/.env') ? (parse_ini_file(__DIR__ . '/.env') ?: []) : [];

$db_host    = app_env('DB_HOST', $_env, 'localhost');
$db_port    = app_env('DB_PORT', $_env, '3306');
$db_name    = app_env('DB_NAME', $_env, 'Steganography');   // case-sensitive on Aiven
$db_user    = app_env('DB_USER', $_env, 'steg_user');
$db_pass    = app_env('DB_PASS', $_env, '');
$db_charset = 'utf8mb4';

unset($_env); // Don't leave credentials in scope

/*
|--------------------------------------------------------------------------
| PDO Options
|--------------------------------------------------------------------------
| Timeout set to 5 seconds so when Aiven or DB is paused/unreachable,
| PHP fails fast with generic 503 rather than hanging until max_execution_time.
*/
$options = [
    PDO::ATTR_ERRMODE            => PDO::ERRMODE_EXCEPTION,
    PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
    PDO::ATTR_EMULATE_PREPARES   => false,
    PDO::ATTR_STRINGIFY_FETCHES  => false,
    PDO::ATTR_TIMEOUT            => 5,
];

/*
|--------------------------------------------------------------------------
| SSL - Use the bundled ca.pem for remote databases (required by Aiven)
|--------------------------------------------------------------------------
| ca.pem is committed to the repo root (not a secret) and is copied
| into the Docker image alongside this file.
*/
$caPem = __DIR__ . '/ca.pem';
$isLocalDb = in_array(strtolower($db_host), ['localhost', '127.0.0.1', '::1'], true);
if (!$isLocalDb) {
    if (!is_file($caPem)) {
        error_log('Database SSL configuration error: CA certificate is missing for remote host.');
        http_response_code(503);
        die('Service temporarily unavailable.');
    }

    $options[PDO::MYSQL_ATTR_SSL_CA]                 = $caPem;
    $options[PDO::MYSQL_ATTR_SSL_VERIFY_SERVER_CERT] = true;
}

/*
|--------------------------------------------------------------------------
| Connection Initialisation
|--------------------------------------------------------------------------
*/
try {
    $dsn = "mysql:host={$db_host};port={$db_port};dbname={$db_name};charset={$db_charset}";
    $pdo = new PDO($dsn, $db_user, $db_pass, $options);
    $pdo->exec("SET time_zone = '+00:00'");
} catch (PDOException $e) {
    // Log real error (server-side only)
    error_log('Database connection error: ' . $e->getMessage());

    // Generic message for users (no info leakage)
    http_response_code(503);
    die('Service temporarily unavailable.');
}
