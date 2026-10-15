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
