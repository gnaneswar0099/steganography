<?php
// ===== nav.php =====
// Shared navigation bar — included by every page.
// BLOCK DIRECT ACCESS
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}
// Expects from including page:
//   $isLoggedIn (bool)
//   $username   (string)
//   $activeNav  (string: 'home' | 'settings' | 'history' | '')
?>
<nav class="top-nav" id="topNav">
    <!-- Logo -->
    <a href="home.php" class="nav-logo">
        <div class="nav-logo-icon"></div><span class="nav-logo-text">Stegano<span class="nav-logo-accent">graphy</span></span>
    </a>

    <!-- Right side -->
    <div class="top-nav-right">
        <?php if ($isLoggedIn): ?>
            <!-- Home (only show when not already on home) -->
            <?php if ($activeNav !== 'home'): ?>
            <a href="home.php" class="nav-btn">
                <i class="fa-solid fa-house"></i>
                <span>Home</span>
            </a>
            <?php endif; ?>
            <!-- History -->
            <a href="history.php"
               class="nav-btn<?php echo ($activeNav === 'history') ? ' nav-btn-active' : ''; ?>">
                <i class="fa-solid fa-clock-rotate-left"></i>
                <span>History</span>
            </a>
            <!-- Settings -->
            <a href="settings.php"
               class="nav-btn<?php echo ($activeNav === 'settings') ? ' nav-btn-active' : ''; ?>">
                <i class="fa-solid fa-gear"></i>
                <span>Settings</span>
            </a>
            <!-- User pill + dropdown -->
            <div class="nav-dropdown-wrap">
                <div class="nav-user-pill" id="navUserPill">
                    <i class="fa-solid fa-user-astronaut"></i>
                    <span class="nav-uname"><?php echo htmlspecialchars($username); ?></span>
                    <i class="fa-solid fa-chevron-down nav-chevron" id="navChevron"></i>
                </div>
                <div class="nav-dropdown" id="navDropdown">
                    <button class="nav-dropdown-item nav-logout-btn" id="navLogoutBtn">
                        <i class="fa-solid fa-right-from-bracket"></i>
                        Logout
                    </button>
                </div>
            </div>
        <?php else: ?>
            <a href="login.php"    class="nav-btn<?php echo ($activeNav === 'login')    ? ' nav-btn-active' : ''; ?>">
                <i class="fa-solid fa-right-to-bracket"></i><span>Login</span>
            </a>
            <a href="register.php" class="nav-btn nav-btn-primary<?php echo ($activeNav === 'register') ? ' nav-btn-active' : ''; ?>">
                <i class="fa-solid fa-user-plus"></i><span>Register</span>
            </a>
        <?php endif; ?>
    </div>
</nav>

<!-- Processing Overlay — shared across all pages -->
<div id="processingOverlay" role="status" aria-live="polite" aria-label="Processing">
    <div class="proc-spinner">
        <div class="proc-ring proc-ring-1"></div>
        <div class="proc-ring proc-ring-2"></div>
        <div class="proc-ring proc-ring-3"></div>
        <div class="proc-lock-icon"><i class="fa-solid fa-lock"></i></div>
    </div>
</div>

<script>
(function () {
    const pill     = document.getElementById('navUserPill');
    const dropdown = document.getElementById('navDropdown');
    const chevron  = document.getElementById('navChevron');
    const logoutBtn = document.getElementById('navLogoutBtn');

    if (pill && dropdown) {
        pill.addEventListener('click', function (e) {
            e.stopPropagation();
            const isOpen = dropdown.classList.contains('nav-dropdown-open');
            dropdown.classList.toggle('nav-dropdown-open', !isOpen);
            if (chevron) chevron.classList.toggle('open', !isOpen);
        });

        document.addEventListener('click', function () {
            dropdown.classList.remove('nav-dropdown-open');
            if (chevron) chevron.classList.remove('open');
        });

        dropdown.addEventListener('click', function (e) {
            e.stopPropagation();
        });
    }

    if (logoutBtn) {
        logoutBtn.addEventListener('click', function () {
            const overlay = document.getElementById('processingOverlay');
            if (overlay) overlay.classList.add('visible');
            document.body.style.overflow = 'hidden';
            window.location.href = 'logout.php';
        });
    }
})();
</script>
