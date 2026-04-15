<?php
// ===== history.php =====
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

if (session_status() === PHP_SESSION_NONE) {
    ini_set('session.gc_maxlifetime', '7200');
    $isSecure = app_is_https();
    session_set_cookie_params([
        'lifetime' => 7200, 'path' => '/', 'domain' => '',
        'secure'   => $isSecure,
        'httponly' => true, 'samesite' => 'Strict',
    ]);
    session_start();
}

if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    header('Location: login.php'); exit;
}
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 7200)) {
    session_unset(); session_destroy();
    header('Location: login.php'); exit;
}
$_SESSION['last_activity'] = time();

require_once 'db.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$userId     = (int) $_SESSION['user_id'];
$activeNav  = 'history';
$isLoggedIn = true;
$username   = $_SESSION['username'] ?? 'User';
$clearSuccess = false;

// ── Handle POST: clear history ───────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        include 'error_session.php'; exit;
    }
    if (($_POST['action'] ?? '') === 'clear_history') {
        try {
            $pdo->prepare("DELETE FROM user_activity_log WHERE user_id = ?")->execute([$userId]);
            $clearSuccess = true;
        } catch (PDOException $e) {
            error_log("History clear error: " . $e->getMessage());
        }
    } elseif (($_POST['action'] ?? '') === 'delete_single') {
        $logId = (int)($_POST['log_id'] ?? 0);
        if ($logId > 0) {
            try {
                $pdo->prepare("DELETE FROM user_activity_log WHERE id = ? AND user_id = ?")->execute([$logId, $userId]);
            } catch (PDOException $e) {
                error_log("Single history delete error: " . $e->getMessage());
            }
        }
    }
}

// ── Filter ───────────────────────────────────────────────────────────────────
$allowedFilters = ['all', 'encode', 'decode'];
$filter = $_GET['filter'] ?? 'all';
if (!in_array($filter, $allowedFilters, true)) $filter = 'all';

// ── Fetch logs ────────────────────────────────────────────────────────────────
$logs = [];
$totalCount = 0;
try {
    if ($filter === 'all') {
        $stmt = $pdo->prepare(
            "SELECT * FROM user_activity_log WHERE user_id = ? ORDER BY performed_at DESC LIMIT 200"
        );
        $stmt->execute([$userId]);
    } else {
        $stmt = $pdo->prepare(
            "SELECT * FROM user_activity_log WHERE user_id = ? AND operation = ? ORDER BY performed_at DESC LIMIT 200"
        );
        $stmt->execute([$userId, $filter]);
    }
    $logs = $stmt->fetchAll();
    $totalCount = count($logs);
} catch (PDOException $e) {
    error_log("History fetch error: " . $e->getMessage());
}
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>History — Steganography</title>
    <meta name="description" content="View your encode and decode operation history." />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
          integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="style.css?v=<?php echo filemtime('style.css'); ?>" />
    <link rel="stylesheet" href="nav.css?v=<?php echo filemtime('nav.css'); ?>" />
</head>
<body class="home-page">

    <div class="grid-container" id="gridContainer"><div class="grid-layer"></div></div>

    <?php include 'nav.php'; ?>

    <main class="history-page-wrap">
        <h1 class="history-page-title">
            <i class="fa-solid fa-clock-rotate-left" style="margin-right:10px;"></i>History
        </h1>

        <?php if ($clearSuccess): ?>
            <div class="settings-alert settings-alert-success" style="margin-bottom:20px;">
                <i class="fa-solid fa-circle-check"></i>
                <span>History cleared successfully.</span>
            </div>
        <?php endif; ?>

        <!-- Filter bar -->
        <div class="history-filter-bar">
            <a href="history.php?filter=all"
               class="history-filter-btn<?php echo $filter === 'all'    ? ' active' : ''; ?>">
                <i class="fa-solid fa-list"></i> All
            </a>
            <a href="history.php?filter=encode"
               class="history-filter-btn<?php echo $filter === 'encode' ? ' active' : ''; ?>">
                <i class="fa-solid fa-file-image"></i> Encode
            </a>
            <a href="history.php?filter=decode"
               class="history-filter-btn<?php echo $filter === 'decode' ? ' active' : ''; ?>">
                <i class="fa-solid fa-magnifying-glass"></i> Decode
            </a>

            <?php if (!empty($logs)): ?>
            <form method="POST" action="history.php<?php echo $filter !== 'all' ? '?filter=' . $filter : ''; ?>"
                  style="margin-left:auto;"
                  onsubmit="return confirm('Clear all operation history? This cannot be undone.');">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="clear_history">
                <button type="submit" class="history-filter-btn history-clear-btn">
                    <i class="fa-solid fa-trash"></i> Clear All
                </button>
            </form>
            <?php endif; ?>
        </div>

        <!-- Table -->
        <div class="history-table-wrap">
            <table class="history-table">
                <thead>
                    <tr>
                        <th>#</th>
                        <th>Operation</th>
                        <th>Cover Image</th>
                        <th>Secret Files</th>
                        <th>LSB Mode</th>
                        <th>Date &amp; Time</th>
                        <th style="width:90px; text-align:right;">Action</th>
                    </tr>
                </thead>
                <tbody>
                    <?php if (empty($logs)): ?>
                    <tr>
                        <td colspan="7">
                            <div class="history-empty" style="padding: 100px 20px;">
                                <i class="fa-solid fa-clock-rotate-left" style="font-size: 4.5rem; margin-bottom: 20px; color: rgba(0,255,255,0.2);"></i>
                                <p style="color: rgba(0,255,255,0.4); font-size: 1.2rem; letter-spacing: 2px;">NO OPERATIONS RECORDED YET</p>
                            </div>
                        </td>
                    </tr>
                    <?php else: ?>
                        <?php
                        $rowNum = $totalCount;
                        foreach ($logs as $row):
                            $files = [];
                            if (!empty($row['secret_file_names'])) {
                                $decoded = json_decode($row['secret_file_names'], true);
                                if (is_array($decoded)) $files = $decoded;
                            }
                            $ts = strtotime($row['performed_at']);
                        ?>
                        <tr>
                            <td style="color:rgba(0,255,255,0.35);font-size:1.2rem;"><?php echo $rowNum--; ?></td>
                            <td>
                                <?php if ($row['operation'] === 'encode'): ?>
                                    <span class="op-badge op-badge-encode">
                                        <i class="fa-solid fa-file-image"></i> Encode
                                    </span>
                                <?php else: ?>
                                    <span class="op-badge op-badge-decode">
                                        <i class="fa-solid fa-magnifying-glass"></i> Decode
                                    </span>
                                <?php endif; ?>
                            </td>
                            <td class="history-cover-cell" title="<?php echo htmlspecialchars($row['cover_image_name']); ?>">
                                <?php echo htmlspecialchars($row['cover_image_name'] ?: '—'); ?>
                            </td>
                            <td>
                                <?php if (empty($files)): ?>
                                    <span style="color:rgba(255,255,255,0.25);">—</span>
                                <?php else: ?>
                                    <ul class="history-files-list">
                                        <?php
                                        $shown = array_slice($files, 0, 3);
                                        $extra = count($files) - count($shown);
                                        foreach ($shown as $fname): ?>
                                            <li>
                                                <i class="fa-solid fa-file-code"></i>
                                                <?php echo htmlspecialchars($fname); ?>
                                            </li>
                                        <?php endforeach; ?>
                                    </ul>
                                    <?php if ($extra > 0): ?>
                                        <div class="history-files-more">+<?php echo $extra; ?> more</div>
                                    <?php endif; ?>
                                <?php endif; ?>
                            </td>
                            <td>
                                <?php if ($row['lsb_mode'] !== null): ?>
                                    <span class="lsb-tag">LSB-<?php echo (int)$row['lsb_mode']; ?></span>
                                <?php else: ?>
                                    <span style="color:rgba(255,255,255,0.25);">—</span>
                                <?php endif; ?>
                            </td>
                            <td>
                                <div class="history-date-main"><?php echo date('d M Y', $ts); ?></div>
                                <div class="history-date-sub"><?php echo date('H:i:s', $ts); ?></div>
                            </td>
                            <td style="text-align:right; vertical-align:middle;">
                                <form method="POST" action="history.php<?php echo $filter !== 'all' ? '?filter=' . $filter : ''; ?>"
                                      onsubmit="return confirm('Delete this record?');" style="margin:0;">
                                    <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                                    <input type="hidden" name="action" value="delete_single">
                                    <input type="hidden" name="log_id" value="<?php echo $row['id']; ?>">
                                    <button type="submit" class="history-del-single" title="Delete record" style="color:#ff4444; border:1px solid rgba(255,68,68,0.4); background:rgba(255,68,68,0.05); padding:8px 16px; font-size:1.15rem; font-weight:bold; font-family:'Courier New',monospace; border-radius:6px; cursor:pointer; text-transform:uppercase;">
                                        <i class="fa-solid fa-trash" style="margin-right:6px;"></i>Delete
                                    </button>
                                </form>
                            </td>
                        </tr>
                        <?php endforeach; ?>
                    <?php endif; ?>
                </tbody>
            </table>
            <?php if (!empty($logs)): ?>
                <div class="history-record-count" style="padding-right:20px; padding-bottom:16px;">
                    Showing <?php echo $totalCount; ?> record<?php echo $totalCount !== 1 ? 's' : ''; ?>
                    <?php if ($filter !== 'all'): ?>
                        (filtered: <?php echo htmlspecialchars($filter); ?>)
                    <?php endif; ?>
                </div>
            <?php endif; ?>
        </div>
    </main>

    <script src="style.js"></script>
</body>
</html>
