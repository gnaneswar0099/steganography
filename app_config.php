<?php
declare(strict_types=1);

function app_is_https(): bool
{
    $https = $_SERVER['HTTPS'] ?? '';
    if ($https !== '' && strtolower((string) $https) !== 'off') {
        return true;
    }

    $forwardedProto = $_SERVER['HTTP_X_FORWARDED_PROTO'] ?? '';
    if (strtolower((string) $forwardedProto) === 'https') {
        return true;
    }

    $forwardedSsl = $_SERVER['HTTP_X_FORWARDED_SSL'] ?? '';
    return strtolower((string) $forwardedSsl) === 'on';
}

function app_env(string $key, ?array $fileEnv = null, ?string $default = null): ?string
{
    $value = getenv($key);
    if ($value !== false && $value !== '') {
        return (string) $value;
    }

    if ($fileEnv !== null && array_key_exists($key, $fileEnv) && (string) $fileEnv[$key] !== '') {
        return (string) $fileEnv[$key];
    }

    return $default;
}

function app_runtime_env(): array
{
    static $fileEnv;

    if ($fileEnv === null) {
        $envPath = __DIR__ . '/.env';
        $fileEnv = is_file($envPath) ? (@parse_ini_file($envPath) ?: []) : [];
    }

    return $fileEnv;
}

function app_max_image_pixels(): int
{
    $val = app_env('MAX_IMAGE_PIXELS', app_runtime_env(), '9000000');
    return max(100000, (int) $val);
}

function app_payload_max_kb(): int
{
    $val = app_env('PAYLOAD_MAX_KB', app_runtime_env(), '200');
    return max(1, (int) $val);
}

function app_encode_max_seconds(): int
{
    $val = app_env('ENCODE_MAX_SECONDS', app_runtime_env(), '100');
    return max(1, (int) $val);
}

function app_payload_capacity_bytes(int $width, int $height, int $lsbMode): int
{
    if (($width <= 0) || ($height <= 0) || !in_array($lsbMode, [1, 2], true)) {
        return 0;
    }

    $totalPixels = $width * $height;
    $availablePixels = $totalPixels - 88;
    if ($availablePixels <= 0) {
        return 0;
    }

    return max(0, (int) floor(($availablePixels * 3 * $lsbMode) / 8) - 16);
}

function app_session_idle_seconds(): int
{
    $minutes = (int) app_env('SESSION_IDLE_MINUTES', app_runtime_env(), '30');
    return max(1, $minutes) * 60;
}

function app_session_absolute_seconds(): int
{
    $hours = (int) app_env('SESSION_ABSOLUTE_HOURS', app_runtime_env(), '8');
    return max(1, $hours) * 3600;
}

function app_start_session(): void
{
    if (session_status() !== PHP_SESSION_NONE) {
        return;
    }

    $gcLifetime = max(app_session_idle_seconds(), app_session_absolute_seconds());
    ini_set('session.use_strict_mode', '1');
    ini_set('session.use_only_cookies', '1');
    ini_set('session.gc_maxlifetime', (string) $gcLifetime);
    session_set_cookie_params([
        'lifetime' => 0,
        'path' => '/',
        'domain' => '',
        'secure' => app_is_https(),
        'httponly' => true,
        'samesite' => 'Strict',
    ]);
    session_start();
}

function app_destroy_session(): void
{
    $_SESSION = [];
    if (ini_get('session.use_cookies')) {
        $params = session_get_cookie_params();
        setcookie(session_name(), '', [
            'expires' => time() - 3600,
            'path' => $params['path'],
            'domain' => $params['domain'],
            'secure' => $params['secure'],
            'httponly' => $params['httponly'],
            'samesite' => $params['samesite'] ?? 'Strict',
        ]);
    }
    if (session_status() === PHP_SESSION_ACTIVE) {
        session_destroy();
    }
}

function app_enforce_session_timeout(bool $requireAuth = false, bool $api = false): void
{
    $authenticated = isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
    if (!$authenticated) {
        if ($requireAuth) {
            if ($api) {
                http_response_code(401);
                header('Content-Type: text/plain; charset=UTF-8');
                exit('Your session expired, please log in again.');
            }
            header('Location: login.php');
            exit;
        }
        return;
    }

    header('Cache-Control: no-store, no-cache, must-revalidate, max-age=0');
    $now = time();
    $loginAt = (int) ($_SESSION['login_at'] ?? 0);
    $lastActivity = (int) ($_SESSION['last_activity'] ?? 0);

    if (
        $loginAt <= 0
        || $lastActivity <= 0
        || ($now - $lastActivity) > app_session_idle_seconds()
        || ($now - $loginAt) > app_session_absolute_seconds()
    ) {
        app_destroy_session();
        if ($api) {
            http_response_code(401);
            header('Content-Type: text/plain; charset=UTF-8');
            exit('Your session expired, please log in again.');
        }
        header('Location: login.php?session_expired=1');
        exit;
    }

    $_SESSION['last_activity'] = $now;
}

function app_email_verification_required(): bool
{
    $value = strtolower(trim((string) app_env('EMAIL_VERIFICATION_REQUIRED', app_runtime_env(), '1')));
    return !in_array($value, ['0', 'false', 'no'], true);
}

function app_public_origin(): string
{
    $configuredUrl = trim((string) app_env('APP_URL', app_runtime_env(), ''));
    $parts = parse_url($configuredUrl);

    if (
        $configuredUrl === ''
        || $parts === false
        || !isset($parts['scheme'], $parts['host'])
        || !in_array(strtolower($parts['scheme']), ['http', 'https'], true)
        || isset($parts['user'])
        || isset($parts['pass'])
        || isset($parts['query'])
        || isset($parts['fragment'])
        || (isset($parts['path']) && $parts['path'] !== '' && $parts['path'] !== '/')
    ) {
        throw new RuntimeException('APP_URL must be a valid HTTP(S) origin without a path or credentials.');
    }

    $origin = strtolower($parts['scheme']) . '://' . strtolower($parts['host']);
    if (isset($parts['port'])) {
        $origin .= ':' . $parts['port'];
    }

    return rtrim($origin, '/');
}
