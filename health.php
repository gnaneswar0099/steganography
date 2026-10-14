<?php
// ===== health.php =====
// Health check endpoint for Render service monitoring.
declare(strict_types=1);

// Prevent caching
header('Cache-Control: no-cache, no-store, must-revalidate');
header('Pragma: no-cache');
header('Expires: 0');
header('Content-Type: application/json; charset=UTF-8');

try {
    require_once __DIR__ . '/db.php';

    // Verify DB connectivity
    $stmt = $pdo->query('SELECT 1');
    if ($stmt === false) {
        throw new RuntimeException('Health query returned false');
    }

    http_response_code(200);
    echo json_encode([
        'status' => 'healthy',
        'time'   => gmdate('Y-m-d\TH:i:s\Z'),
    ]);
} catch (Throwable $e) {
    error_log('Health check failed: ' . $e->getMessage());

    http_response_code(503);
    echo json_encode([
        'status'  => 'unhealthy',
        'message' => 'Service temporarily unavailable',
    ]);
}