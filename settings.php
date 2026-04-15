<?php
// ===== settings.php =====
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

// Auth guard
if (!isset($_SESSION['user_id']) || empty($_SESSION['user_id'])) {
    header('Location: login.php');
    exit;
}
if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 7200)) {
    session_unset();
    session_destroy();
    header('Location: login.php');
    exit;
}
$_SESSION['last_activity'] = time();

require_once 'db.php';

if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}

$userId     = (int)$_SESSION['user_id'];
$activeNav  = 'settings';
$isLoggedIn = true;

// Fetch current user row
try {
    $stmt = $pdo->prepare("SELECT username, email FROM users WHERE id = ?");
    $stmt->execute([$userId]);
    $user = $stmt->fetch();
} catch (PDOException $e) {
    error_log("Settings fetch: " . $e->getMessage());
    $user = ['username' => $_SESSION['username'] ?? '', 'email' => ''];
}

$username = $user['username'] ?? ($_SESSION['username'] ?? 'User');

// Alerts: [{type:'success'|'error', section:'profile'|'password'|'danger', msg:'...'}]
$alerts = [];

// ── Handle POST ──────────────────────────────────────────────────────────────
if ($_SERVER['REQUEST_METHOD'] === 'POST') {
    if (empty($_POST['csrf_token']) || !hash_equals($_SESSION['csrf_token'], $_POST['csrf_token'])) {
        include 'error_session.php';
        exit;
    }

    $action = $_POST['action'] ?? '';

    // ── Change Username ────────────────────────────────────────────────────
    if ($action === 'change_username') {
        $newUsername = trim($_POST['new_username'] ?? '');
        if (empty($newUsername)) {
            $alerts[] = ['type' => 'error', 'section' => 'profile', 'msg' => 'Username cannot be empty.'];
        } elseif (!preg_match('/^[a-zA-Z0-9_]{3,50}$/', $newUsername)) {
            $alerts[] = ['type' => 'error', 'section' => 'profile', 'msg' => 'Username must be 3–50 characters (letters, numbers, underscores only).'];
        } elseif ($newUsername === $user['username']) {
            $alerts[] = ['type' => 'error', 'section' => 'profile', 'msg' => 'New username must be different from your current username.'];
        } else {
            try {
                $chk = $pdo->prepare("SELECT id FROM users WHERE username = ? AND id != ?");
                $chk->execute([$newUsername, $userId]);
                if ($chk->fetch()) {
                    $alerts[] = ['type' => 'error', 'section' => 'profile', 'msg' => 'That username is already taken. Please choose another.'];
                } else {
                    $pdo->prepare("UPDATE users SET username = ? WHERE id = ?")->execute([$newUsername, $userId]);
                    $_SESSION['username'] = $newUsername;
                    $username             = $newUsername;
                    $user['username']     = $newUsername;
                    $alerts[] = ['type' => 'success', 'section' => 'profile', 'msg' => 'Username updated successfully.'];
                }
            } catch (PDOException $e) {
                error_log("Settings username error: " . $e->getMessage());
                $alerts[] = ['type' => 'error', 'section' => 'profile', 'msg' => 'A system error occurred. Please try again.'];
            }
        }
    }

    // ── Change Password ────────────────────────────────────────────────────
    elseif ($action === 'change_password') {
        $currentPw    = $_POST['current_password'] ?? '';
        $newPw        = $_POST['new_password']      ?? '';
        $confirmPw    = $_POST['confirm_password']  ?? '';
        $pwError      = null;
        $fetchSuccess = false;

        try {
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $row          = $stmt->fetch();
            $fetchSuccess = true;
        } catch (PDOException $e) {
            error_log("Settings pw fetch: " . $e->getMessage());
            $alerts[] = ['type' => 'error', 'section' => 'password', 'msg' => 'A system error occurred.'];
        }

        if ($fetchSuccess) {
            if (!$row || !password_verify($currentPw, $row['password_hash'])) {
                $pwError = 'Current password is incorrect.';
            } elseif ($newPw !== $confirmPw) {
                $pwError = 'New passwords do not match.';
            } elseif (strlen($newPw) < 8 || !preg_match('/[A-Z]/', $newPw) || !preg_match('/[a-z]/', $newPw) || !preg_match('/[0-9]/', $newPw) || !preg_match('/[\W_]/', $newPw)) {
                $pwError = 'Password must be at least 8 characters and contain uppercase, lowercase, a number, and a special character.';
            } elseif ($newPw === $currentPw) {
                $pwError = 'New password must be different from your current password.';
            }

            if ($pwError) {
                $alerts[] = ['type' => 'error', 'section' => 'password', 'msg' => $pwError];
            } else {
                try {
                    $pdo->prepare("UPDATE users SET password_hash = ? WHERE id = ?")->execute([password_hash($newPw, PASSWORD_DEFAULT), $userId]);
                    $alerts[] = ['type' => 'success', 'section' => 'password', 'msg' => 'Password updated successfully.'];
                } catch (PDOException $e) {
                    error_log("Settings pw update: " . $e->getMessage());
                    $alerts[] = ['type' => 'error', 'section' => 'password', 'msg' => 'A system error occurred. Please try again.'];
                }
            }
        }
    }

    // ── Delete Account ─────────────────────────────────────────────────────
    elseif ($action === 'delete_account') {
        $confirmPw    = $_POST['delete_confirm_password'] ?? '';
        $fetchSuccess = false;
        try {
            $stmt = $pdo->prepare("SELECT password_hash FROM users WHERE id = ?");
            $stmt->execute([$userId]);
            $row          = $stmt->fetch();
            $fetchSuccess = true;
        } catch (PDOException $e) {
            error_log("Settings delete fetch: " . $e->getMessage());
            $alerts[] = ['type' => 'error', 'section' => 'danger', 'msg' => 'A system error occurred.'];
        }

        if ($fetchSuccess) {
            if (!$row || !password_verify($confirmPw, $row['password_hash'])) {
                $alerts[] = ['type' => 'error', 'section' => 'danger', 'msg' => 'Incorrect password. Account not deleted.'];
            } else {
                try {
                    $pdo->beginTransaction();
                    $pdo->prepare("DELETE FROM user_activity_log WHERE user_id = ?")->execute([$userId]);
                    $pdo->prepare("DELETE FROM users WHERE id = ?")->execute([$userId]);
                    $pdo->commit();
                    $_SESSION = [];
                    session_destroy();
                    header('Location: login.php');
                    exit;
                } catch (PDOException $e) {
                    if ($pdo->inTransaction()) {
                        $pdo->rollBack();
                    }
                    error_log("Settings delete: " . $e->getMessage());
                    $alerts[] = ['type' => 'error', 'section' => 'danger', 'msg' => 'A system error occurred during deletion.'];
                }
            }
        }
    }
}

// ── Helper ───────────────────────────────────────────────────────────────────
function renderAlert(array $alerts, string $section): void
{
    foreach ($alerts as $a) {
        if ($a['section'] !== $section) continue;
        $cls  = $a['type'] === 'success' ? 'settings-alert-success' : 'settings-alert-error';
        $icon = $a['type'] === 'success' ? 'fa-circle-check'        : 'fa-triangle-exclamation';
        echo '<div class="settings-alert ' . $cls . '">'
           . '<i class="fa-solid ' . $icon . '"></i>'
           . '<span>' . htmlspecialchars($a['msg']) . '</span>'
           . '</div>';
    }
}

// Determine which tab to open on page load (auto-jump to the tab with an alert)
$openTab = 'profile';
foreach ($alerts as $a) { $openTab = $a['section']; break; }
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Settings — Steganography</title>
    <meta name="description" content="Manage your account profile and security settings." />
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
          integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
          crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="style.css?v=<?php echo filemtime('style.css'); ?>" />
    <link rel="stylesheet" href="nav.css?v=<?php echo filemtime('nav.css'); ?>" />

    <style>
    /* ══════════════════════════════════════════════════════════
       SETTINGS DASHBOARD  —  scoped, self-contained styles
    ══════════════════════════════════════════════════════════ */

    /* Page heading */
    .settings-heading {
        width: 94%;
        max-width: 1200px;
        margin: 38px auto 0;
        position: relative;
        z-index: 10;
    }
    .settings-heading h1 {
        font-size: 3.8rem;
        color: #00ffff;
        letter-spacing: 6px;
        text-transform: uppercase;
        text-shadow: 0 0 22px rgba(0,255,255,0.45);
        display: flex;
        align-items: center;
        gap: 14px;
    }
    .settings-heading p {
        color: rgba(0,255,255,0.5);
        font-size: 1.35rem;
        letter-spacing: 2.5px;
        margin-top: 8px;
    }

    /* Dashboard wrapper */
    .settings-wrap {
        display: flex;
        gap: 32px;
        width: 94%;
        max-width: 1200px;
        margin: 32px auto 80px;
        align-items: flex-start;
        position: relative;
        z-index: 10;
    }

    /* ── Sidebar ── */
    .settings-sidebar {
        width: 270px;
        flex-shrink: 0;
        background: rgba(10,14,39,0.88);
        border: 1px solid rgba(0,255,255,0.14);
        border-radius: 22px;
        overflow: hidden;
        backdrop-filter: blur(14px);
        box-shadow: 0 0 40px rgba(0,255,255,0.07);
        position: sticky;
        top: 90px;
    }
    .settings-sidebar-header {
        padding: 28px 22px 20px;
        border-bottom: 1px solid rgba(0,255,255,0.08);
        display: flex;
        flex-direction: column;
        align-items: center;
        text-align: center;
    }
    .settings-avatar {
        width: 80px;
        height: 80px;
        border-radius: 50%;
        background: linear-gradient(135deg,rgba(0,255,255,0.18),rgba(0,255,136,0.18));
        border: 2px solid rgba(0,255,255,0.45);
        display: flex;
        align-items: center;
        justify-content: center;
        font-size: 2.2rem;
        color: #00ffff;
        margin-bottom: 14px;
        box-shadow: 0 0 22px rgba(0,255,255,0.25);
    }
    .settings-sidebar-name {
        color: #fff;
        font-size: 1.5rem;
        font-weight: bold;
        letter-spacing: 1.2px;
        white-space: nowrap;
        overflow: hidden;
        text-overflow: ellipsis;
        max-width: 100%;
    }

    .settings-nav { padding: 12px 0; }
    .settings-nav-item {
        display: flex;
        align-items: center;
        gap: 13px;
        padding: 15px 24px;
        cursor: pointer;
        color: rgba(255,255,255,0.45);
        font-size: 1.2rem;
        letter-spacing: 1.8px;
        text-transform: uppercase;
        transition: all 0.22s ease;
        border-left: 3px solid transparent;
        user-select: none;
    }
    .settings-nav-item i { font-size: 1.55rem; width: 26px; text-align: center; flex-shrink: 0; }
    .settings-nav-item:hover { color: #00ffff; background: rgba(0,255,255,0.05); }
    .settings-nav-item.active {
        color: #00ffff;
        background: rgba(0,255,255,0.08);
        border-left-color: #00ffff;
        text-shadow: 0 0 8px rgba(0,255,255,0.35);
    }
    .settings-nav-item.active i { filter: drop-shadow(0 0 5px rgba(0,255,255,0.65)); }
    .settings-nav-divider { height: 1px; background: rgba(0,255,255,0.07); margin: 8px 18px; }
    .settings-nav-item.danger-item { color: rgba(255,68,68,0.55); }
    .settings-nav-item.danger-item:hover { color: #ff4444; background: rgba(255,68,68,0.06); }
    .settings-nav-item.danger-item.active {
        color: #ff4444; border-left-color: #ff4444; background: rgba(255,68,68,0.08);
    }

    /* ── Content panel ── */
    .settings-panel { flex: 1; min-width: 0; }

    .settings-tab { display: none; animation: stgFadeIn 0.28s ease; }
    .settings-tab.tab-active { display: block; }

    @keyframes stgFadeIn {
        from { opacity: 0; transform: translateY(10px); }
        to   { opacity: 1; transform: translateY(0); }
    }

    /* Card */
    .settings-card {
        background: rgba(10,14,39,0.88);
        border: 1px solid rgba(0,255,255,0.16);
        border-radius: 22px;
        padding: 40px 44px;
        backdrop-filter: blur(14px);
        box-shadow: 0 0 50px rgba(0,255,255,0.05);
        margin-bottom: 28px;
    }
    .settings-card.danger-card {
        border-color: rgba(255,68,68,0.2);
        box-shadow: 0 0 50px rgba(255,68,68,0.05);
    }

    /* Card title */
    .settings-card-title {
        display: flex;
        align-items: center;
        gap: 13px;
        font-size: 1.5rem;
        font-weight: bold;
        letter-spacing: 3.5px;
        text-transform: uppercase;
        color: #00ffff;
        margin-bottom: 30px;
        padding-bottom: 18px;
        border-bottom: 1px solid rgba(0,255,255,0.1);
    }
    .settings-card-title i { font-size: 1.65rem; }
    .danger-card .settings-card-title { color: rgba(255,68,68,0.8); border-bottom-color: rgba(255,68,68,0.1); }

    /* Field */
    .settings-field { margin-bottom: 26px; }
    .settings-field label {
        display: flex;
        align-items: center;
        gap: 9px;
        color: rgba(0,255,255,0.65);
        font-size: 1.2rem;
        letter-spacing: 2.5px;
        text-transform: uppercase;
        margin-bottom: 10px;
        font-weight: bold;
    }
    .settings-readonly-badge {
        font-size: 1rem;
        color: rgba(255,255,255,0.3);
        background: rgba(255,255,255,0.05);
        padding: 3px 10px;
        border-radius: 20px;
        border: 1px solid rgba(255,255,255,0.08);
        letter-spacing: 1px;
    }
    .settings-input-wrapper { position: relative; display: flex; align-items: center; }
    .settings-input {
        width: 100%;
        padding: 16px 20px;
        background: rgba(0,255,255,0.04);
        border: 1px solid rgba(0,255,255,0.18);
        border-radius: 12px;
        color: #dde8e8;
        font-family: 'Courier New', monospace;
        font-size: 1.35rem;
        outline: none;
        transition: all 0.28s ease;
        letter-spacing: 0.5px;
    }
    .settings-input:focus {
        border-color: #00ffff;
        background: rgba(0,255,255,0.07);
        box-shadow: 0 0 20px rgba(0,255,255,0.16);
        color: #fff;
    }
    .settings-input[readonly] {
        color: rgba(255,255,255,0.25);
        cursor: default;
        border-style: dashed;
    }
    .settings-input-wrapper .settings-input { padding-right: 48px; }
    .settings-toggle-icon {
        position: absolute;
        right: 16px;
        color: rgba(0,255,255,0.45);
        font-size: 1.2rem;
        cursor: pointer;
        transition: color 0.2s;
        z-index: 2;
    }
    .settings-toggle-icon:hover { color: #00ffff; }

    /* Buttons */
    .settings-btn {
        display: inline-flex;
        align-items: center;
        gap: 10px;
        padding: 14px 30px;
        background: linear-gradient(135deg,rgba(0,255,255,0.1),rgba(0,255,136,0.1));
        border: 1px solid rgba(0,255,255,0.3);
        border-radius: 12px;
        color: #00ffff;
        font-family: 'Courier New', monospace;
        font-size: 1.15rem;
        font-weight: bold;
        letter-spacing: 2.5px;
        text-transform: uppercase;
        cursor: pointer;
        transition: all 0.28s ease;
        margin-top: 6px;
    }
    .settings-btn:hover {
        background: linear-gradient(135deg,rgba(0,255,255,0.2),rgba(0,255,136,0.2));
        box-shadow: 0 0 22px rgba(0,255,255,0.32);
        transform: translateY(-2px);
        border-color: #00ffff;
    }
    .settings-btn:disabled {
        opacity: 0.4;
        cursor: not-allowed;
        transform: none !important;
        box-shadow: none !important;
    }
    .settings-btn-danger {
        background: linear-gradient(135deg,rgba(255,68,68,0.1),rgba(180,0,0,0.1));
        border-color: rgba(255,68,68,0.35);
        color: #ff4444;
    }
    .settings-btn-danger:hover {
        background: linear-gradient(135deg,rgba(255,68,68,0.2),rgba(180,0,0,0.15));
        box-shadow: 0 0 22px rgba(255,68,68,0.36);
        border-color: #ff4444;
    }

    /* Alert banners */
    .settings-alert {
        display: flex;
        align-items: center;
        gap: 12px;
        padding: 14px 20px;
        border-radius: 12px;
        font-size: 1.25rem;
        margin-bottom: 22px;
        letter-spacing: 0.5px;
        animation: stgFadeIn 0.3s ease;
    }
    .settings-alert-success { background:rgba(0,255,136,0.07); border:1px solid rgba(0,255,136,0.28); color:#00ff88; }
    .settings-alert-error   { background:rgba(255,68,68,0.07);  border:1px solid rgba(255,68,68,0.28);  color:#ff4444; }

    /* Password rules box */
    #passwordRules {
        display: none;
        flex-direction: column;
        gap: 8px;
        background: rgba(0,0,0,0.22);
        padding: 14px 18px;
        border: 1px solid rgba(0,255,255,0.12);
        border-radius: 9px;
        font-size: 1rem;
        letter-spacing: 0.5px;
        margin-bottom: 16px;
    }

    /* Password match message */
    #pw-match-msg {
        margin-top: 8px;
        font-size: 1.2rem;
        font-weight: bold;
        min-height: 24px;
        transition: color 0.2s;
    }

    /* Danger info block */
    .danger-info {
        color: rgba(255,255,255,0.5);
        font-size: 1.25rem;
        line-height: 1.95;
        margin-bottom: 20px;
        padding: 16px 20px;
        background: rgba(255,68,68,0.05);
        border-radius: 10px;
        border: 1px solid rgba(255,68,68,0.1);
    }
    .danger-info strong { color: #ff4444; }

    /* ── Modal ── */
    .modal-overlay {
        display: none;
        position: fixed;
        inset: 0;
        background: rgba(0,0,0,0.78);
        backdrop-filter: blur(6px);
        z-index: 9000;
        align-items: center;
        justify-content: center;
    }
    .modal-overlay.open { display: flex; }
    .modal-box {
        background: rgba(10,14,39,0.97);
        border: 1px solid rgba(255,68,68,0.38);
        border-radius: 18px;
        padding: 36px 38px;
        max-width: 600px;
        width: 90%;
        box-shadow: 0 0 55px rgba(255,68,68,0.18);
        animation: stgFadeIn 0.3s ease;
    }
    .modal-box h3 {
        color: #ff4444;
        font-size: 1.6rem;
        letter-spacing: 3px;
        text-transform: uppercase;
        margin-bottom: 14px;
    }
    .modal-box p {
        color: rgba(255,255,255,0.6);
        font-size: 1rem;
        line-height: 1.85;
        margin-bottom: 20px;
    }
    .modal-actions {
        display: flex;
        flex-flow: row nowrap;
        gap: 16px;
        justify-content: flex-end;
        margin-top: 16px;
    }
    </style>
</head>
<body class="home-page">

    <div class="grid-container" id="gridContainer"><div class="grid-layer"></div></div>
    <?php include 'nav.php'; ?>

    <!-- PAGE HEADING -->
    <div class="settings-heading">
        <h1><i class="fa-solid fa-gear"></i> Settings</h1>
        <p>Manage your account and security preferences</p>
    </div>

    <!-- TWO-COLUMN DASHBOARD -->
    <div class="settings-wrap">

        <!-- ── SIDEBAR ── -->
        <aside class="settings-sidebar">
            <div class="settings-sidebar-header">
                <div class="settings-avatar">
                    <i class="fa-solid fa-user"></i>
                </div>
                <div class="settings-sidebar-name"><?php echo htmlspecialchars($username); ?></div>
            </div>
            <nav class="settings-nav" id="settingsNav">
                <div class="settings-nav-item active" data-tab="profile" id="nav-profile">
                    <i class="fa-solid fa-id-card"></i> Profile
                </div>
                <div class="settings-nav-item" data-tab="password" id="nav-password">
                    <i class="fa-solid fa-lock"></i> Password
                </div>
                <div class="settings-nav-divider"></div>
                <div class="settings-nav-item danger-item" data-tab="danger" id="nav-danger">
                    <i class="fa-solid fa-trash"></i> Delete Account
                </div>
            </nav>
        </aside>

        <!-- ── CONTENT PANEL ── -->
        <main class="settings-panel">

            <!-- TAB: Profile -->
            <div class="settings-tab tab-active" id="tab-profile">
                <div class="settings-card">
                    <div class="settings-card-title">
                        <i class="fa-solid fa-id-card"></i> Account Profile
                    </div>

                    <?php renderAlert($alerts, 'profile'); ?>

                    <!-- Email (read-only) -->
                    <div class="settings-field">
                        <label for="display_email">
                            Email Address
                            <span class="settings-readonly-badge"><i class="fa-solid fa-lock"></i>&nbsp;Read-only</span>
                        </label>
                        <div class="settings-input-wrapper">
                            <input type="email" id="display_email" class="settings-input"
                                   value="<?php echo htmlspecialchars($user['email'] ?? ''); ?>"
                                   readonly tabindex="-1" />
                        </div>
                    </div>

                    <!-- Change Username -->
                    <form method="POST" action="settings.php" id="formUsername">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="change_username">
                        <div class="settings-field">
                            <label for="new_username">Username</label>
                            <div class="settings-input-wrapper">
                                <input type="text" id="new_username" name="new_username" class="settings-input"
                                       value="<?php echo htmlspecialchars($user['username'] ?? ''); ?>"
                                       autocomplete="off" required
                                       placeholder="3–50 chars · letters / numbers / underscore" />
                            </div>
                        </div>
                        <button type="submit" class="settings-btn">
                            <i class="fa-solid fa-floppy-disk"></i> Save Username
                        </button>
                    </form>
                </div>
            </div>

            <!-- TAB: Password -->
            <div class="settings-tab" id="tab-password">
                <div class="settings-card">
                    <div class="settings-card-title">
                        <i class="fa-solid fa-lock"></i> Change Password
                    </div>

                    <?php renderAlert($alerts, 'password'); ?>

                    <form method="POST" action="settings.php" id="formPassword">
                        <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                        <input type="hidden" name="action" value="change_password">

                        <div class="settings-field">
                            <label for="current_password">Current Password</label>
                            <div class="settings-input-wrapper">
                                <input type="password" id="current_password" name="current_password"
                                       class="settings-input" placeholder="Enter your current password"
                                       autocomplete="current-password" required />
                                <i class="fa-solid fa-eye settings-toggle-icon" data-target="current_password"></i>
                            </div>
                        </div>

                        <div class="settings-field">
                            <label for="new_password">New Password</label>
                            <div class="settings-input-wrapper" style="margin-bottom:10px;">
                                <input type="password" id="new_password" name="new_password"
                                       class="settings-input" placeholder="Create a strong new password"
                                       autocomplete="new-password" required />
                                <i class="fa-solid fa-eye settings-toggle-icon" data-target="new_password"></i>
                            </div>
                            <div id="passwordRules">
                                <span id="rule-length"  style="color:rgba(255,255,255,0.38);">&#9679; At least 8 characters</span>
                                <span id="rule-upper"   style="color:rgba(255,255,255,0.38);">&#9679; At least One Uppercase Letter</span>
                                <span id="rule-lower"   style="color:rgba(255,255,255,0.38);">&#9679; At least One Lowercase Letter</span>
                                <span id="rule-number"  style="color:rgba(255,255,255,0.38);">&#9679; At least One Number</span>
                                <span id="rule-special" style="color:rgba(255,255,255,0.38);">&#9679; At least One Special Symbol</span>
                            </div>
                        </div>

                        <div class="settings-field" style="margin-bottom: 0;">
                            <label for="confirm_password">Confirm New Password</label>
                            <div class="settings-input-wrapper">
                                <input type="password" id="confirm_password" name="confirm_password"
                                       class="settings-input" placeholder="Repeat your new password"
                                       autocomplete="new-password" required />
                                <i class="fa-solid fa-eye settings-toggle-icon" data-target="confirm_password"></i>
                            </div>
                            <div id="pw-match-msg"></div>
                        </div>

                        <button type="submit" class="settings-btn" id="pwSubmitBtn" disabled>
                            <i class="fa-solid fa-shield"></i> Update Password
                        </button>
                    </form>
                </div>
            </div>

            <!-- TAB: Delete Account -->
            <div class="settings-tab" id="tab-danger">
                <div class="settings-card danger-card">
                    <div class="settings-card-title">
                        <i class="fa-solid fa-trash" style="color:#ff4444;"></i>
                        <span>Delete Account</span>
                    </div>

                    <?php renderAlert($alerts, 'danger'); ?>

                    <div class="danger-info">
                        Permanently delete your account and all associated data.
                        This action <strong>cannot be undone</strong>. All your encode / decode
                        history will be erased immediately upon confirmation.
                    </div>
                    <button type="button" id="openDeleteModal" class="settings-btn settings-btn-danger">
                        <i class="fa-solid fa-trash"></i> Delete My Account
                    </button>
                </div>
            </div>

        </main><!-- /.settings-panel -->
    </div><!-- /.settings-wrap -->

    <!-- ── Delete Account Modal ── -->
    <div class="modal-overlay" id="deleteModal">
        <div class="modal-box">
            <h3><i class="fa-solid fa-skull" style="margin-right:8px;"></i>Delete Account</h3>
            <p>
                You are about to <strong style="color:#ff4444;">permanently delete</strong> your account.
                All your encode&nbsp;/&nbsp;decode history will be erased and you will be logged out immediately.
                To confirm, enter your current password below.
            </p>
            <form method="POST" action="settings.php" id="formDelete">
                <input type="hidden" name="csrf_token" value="<?php echo htmlspecialchars($_SESSION['csrf_token']); ?>">
                <input type="hidden" name="action" value="delete_account">
                <div class="settings-field">
                    <label for="delete_confirm_password">Confirm Password</label>
                    <div class="settings-input-wrapper">
                        <input type="password" id="delete_confirm_password" name="delete_confirm_password"
                               class="settings-input" placeholder="Enter your password to confirm"
                               autocomplete="current-password" required />
                        <i class="fa-solid fa-eye settings-toggle-icon" data-target="delete_confirm_password"></i>
                    </div>
                </div>
                <div class="modal-actions">
                    <button type="button" id="closeDeleteModal" class="settings-btn">
                        <i class="fa-solid fa-xmark"></i> Cancel
                    </button>
                    <button type="submit" class="settings-btn settings-btn-danger">
                        <i class="fa-solid fa-trash"></i> Yes, Delete
                    </button>
                </div>
            </form>
        </div>
    </div>

    <script src="style.js"></script>
    <script>
    // ── Tab switching ─────────────────────────────────────────────────────────
    const navItems = document.querySelectorAll('.settings-nav-item');
    const allTabs  = document.querySelectorAll('.settings-tab');

    function activateTab(tabId) {
        navItems.forEach(function(n) { n.classList.remove('active'); });
        allTabs.forEach(function(t)  { t.classList.remove('tab-active'); });
        const navEl = document.querySelector('.settings-nav-item[data-tab="' + tabId + '"]');
        const tabEl = document.getElementById('tab-' + tabId);
        if (navEl) navEl.classList.add('active');
        if (tabEl) tabEl.classList.add('tab-active');
    }

    navItems.forEach(function(item) {
        item.addEventListener('click', function() { activateTab(item.dataset.tab); });
    });

    // Auto-open the tab that received a POST alert
    activateTab('<?php echo $openTab; ?>');

    // ── Eye toggle ────────────────────────────────────────────────────────────
    document.querySelectorAll('.settings-toggle-icon').forEach(function(icon) {
        icon.addEventListener('click', function() {
            var input = document.getElementById(icon.dataset.target);
            if (!input) return;
            var isPass = input.type === 'password';
            input.type = isPass ? 'text' : 'password';
            icon.classList.toggle('fa-eye',      !isPass);
            icon.classList.toggle('fa-eye-slash',  isPass);
        });
    });

    // ── Live password strength + match ────────────────────────────────────────
    var newPw       = document.getElementById('new_password');
    var confirmPw   = document.getElementById('confirm_password');
    var matchMsg    = document.getElementById('pw-match-msg');
    var pwSubmitBtn = document.getElementById('pwSubmitBtn');
    var pwRules     = document.getElementById('passwordRules');

    const rules = {
        length:  { el: document.getElementById('rule-length'),  regex: /.{8,}/,  label: 'At least 8 characters' },
        upper:   { el: document.getElementById('rule-upper'),   regex: /[A-Z]/,  label: 'At least One Uppercase Letter' },
        lower:   { el: document.getElementById('rule-lower'),   regex: /[a-z]/,  label: 'At least One Lowercase Letter' },
        number:  { el: document.getElementById('rule-number'),  regex: /[0-9]/,  label: 'At least One Number' },
        special: { el: document.getElementById('rule-special'), regex: /[\W_]/,  label: 'At least One Special Symbol' }
    };

    if (newPw) {
        newPw.addEventListener('focus', function() { if (pwRules) pwRules.style.display = 'flex'; });
        newPw.addEventListener('blur',  function() { if (newPw && !newPw.value && pwRules) pwRules.style.display = 'none'; });
        newPw.addEventListener('input', validatePassword);
    }
    if (confirmPw) confirmPw.addEventListener('input', validatePassword);

    function validatePassword() {
        if (!newPw || !confirmPw || !matchMsg) return;
        const val = newPw.value;
        if (val.length > 0 && pwRules) pwRules.style.display = 'flex';

        let allValid = true;
        for (const key in rules) {
            const rule = rules[key];
            if (!rule.el) continue;
            if (rule.regex.test(val)) {
                rule.el.style.color = '#00ff88';
                rule.el.innerHTML = '<i class="fa-solid fa-check"></i> ' + rule.label;
            } else {
                rule.el.style.color = 'rgba(255,255,255,0.38)';
                rule.el.innerHTML = '&#9679; ' + rule.label;
                allValid = false;
            }
        }

        let match = false;
        if (confirmPw.value) {
            match = newPw.value === confirmPw.value;
            matchMsg.textContent = match ? '\u2714 Passwords match' : '\u2718 Passwords do not match';
            matchMsg.style.color = match ? '#00ff88' : '#ff4444';
        } else {
            matchMsg.textContent = '';
        }

        if (pwSubmitBtn) {
            pwSubmitBtn.disabled = !(val.length > 0 && allValid && match);
            pwSubmitBtn.style.opacity = pwSubmitBtn.disabled ? '0.4' : '1';
            pwSubmitBtn.style.cursor  = pwSubmitBtn.disabled ? 'not-allowed' : 'pointer';
        }
    }
    window.addEventListener('DOMContentLoaded', validatePassword);

    // ── Delete modal ─────────────────────────────────────────────────────────
    var modal = document.getElementById('deleteModal');
    document.getElementById('openDeleteModal').addEventListener('click', function() {
        modal.classList.add('open');
    });
    document.getElementById('closeDeleteModal').addEventListener('click', function() {
        modal.classList.remove('open');
    });
    modal.addEventListener('click', function(e) {
        if (e.target === modal) modal.classList.remove('open');
    });
    </script>
</body>
</html>
