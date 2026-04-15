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
