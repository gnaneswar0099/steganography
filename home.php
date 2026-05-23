<?php
// ===== home.php =====
// UI ONLY - NO BACKEND CRYPTO/STEGO LOGIC HERE
declare(strict_types=1);

require_once __DIR__ . '/app_config.php';

if (session_status() === PHP_SESSION_NONE) {
    // Session Security
    $isHttps = app_is_https();
    session_set_cookie_params([
        'lifetime' => 7200,
        'path' => '/',
        'domain' => '',
        'secure' => $isHttps,
        'httponly' => true,
        'samesite' => 'Strict'
    ]);
    session_start();
}

// ── Server-side session timeout (2 hours = 7200 s) ───────────────────────────
// Only enforced for authenticated users; guests may browse home.php freely.
if (isset($_SESSION['user_id'])) {
    if (isset($_SESSION['last_activity']) && (time() - $_SESSION['last_activity'] > 7200)) {
        // Session has been idle for more than 2 hours — invalidate it
        session_unset();
        session_destroy();
        header("Location: login.php");
        exit;
    }
    $_SESSION['last_activity'] = time(); // Rolling update — reset the idle clock
}

// Check if user is authenticated (but do NOT redirect if not)
$isLoggedIn = isset($_SESSION['user_id']) && !empty($_SESSION['user_id']);
$username = $isLoggedIn ? ($_SESSION['username'] ?? 'User') : 'Guest';
$activeNav = 'home';

// CSRF Token Generation (Only allowed backend logic in home.php)
if (empty($_SESSION['csrf_token'])) {
    $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
}
$csrf_token = $_SESSION['csrf_token'];
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
    <title>Steganography</title>

    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <link rel="stylesheet" href="style.css?v=<?php echo filemtime('style.css'); ?>" />
    <link rel="stylesheet" href="nav.css?v=<?php echo filemtime('nav.css'); ?>" />

</head>

<body class="home-page">

    <!-- GRID BACKGROUND -->
    <div class="grid-container" id="gridContainer">
        <div class="grid-layer"></div>
    </div>

    <?php include 'nav.php'; ?>

    <!-- HEADER -->
    <header>
        <h1>Image Steganography</h1>
        <p>Select an operation to continue</p>
    </header>

    <!-- CARD CONTAINER -->
    <div class="card-container">

        <!-- ENCODE CARD -->
        <div class="card encode" data-mode="encode" id="card-encode">
            <div class="glow"></div>
            <h2>Encode Image</h2>
            <p>Hide secret files inside an image securely.</p>
            <span class="action">Proceed →</span>
        </div>

        <!-- DECODE CARD -->
        <div class="card decode" data-mode="decode" id="card-decode">
            <div class="glow"></div>
            <h2>Decode Image</h2>
            <p>Extract hidden information from a steganographic image.</p>
            <span class="action">Proceed →</span>
        </div>

    </div>

    <!-- DYNAMIC CONTENT -->
    <div id="contentArea" class="content-area"></div>

    <!-- TOAST CONTAINER -->
    <div id="toast-container" class="toast-container"></div>

    <script src="style.js"></script>
    <script>
        // Pass PHP session status to JS
        const IS_LOGGED_IN = <?php echo $isLoggedIn ? 'true' : 'false'; ?>;
        const CSRF_TOKEN = "<?php echo $csrf_token; ?>";

        function showLoader(mode) {
            const overlay = document.getElementById('processingOverlay');
            if (overlay) overlay.classList.add('visible');
            document.body.style.overflow = 'hidden';
        }

        function hideLoader() {
            const overlay = document.getElementById('processingOverlay');
            if (overlay) overlay.classList.remove('visible');
            document.body.style.overflow = '';
        }
        /* ─────────────────────────────────────────────────────────────── */

        document.addEventListener("DOMContentLoaded", () => {
            // Handle card clicks via event delegation
            const cardContainer = document.querySelector('.card-container');
            if (cardContainer) {
                cardContainer.addEventListener('click', (e) => {
                    const card = e.target.closest('.card');
                    if (card) {
                        handleModeClick(card.dataset.mode);
                    }
                });
            }
        });

        let currentMode = null;
        let secretFilesArray = [];
        let currentCoverImageWidth = 0;
        let currentCoverImageHeight = 0;

        function showToast(msg, type = 'error') {
            const container = document.getElementById('toast-container');
            if (!container) return;
            const toast = document.createElement('div');
            toast.className = `toast toast-${type}`;
            const icon = type === 'success' ? 'fa-circle-check' : 'fa-circle-exclamation';
            toast.innerHTML = `<i class="fa-solid ${icon}"></i> &nbsp; ${msg}`;
            container.appendChild(toast);
            setTimeout(() => toast.remove(), 5000);
        }

        function updateCardStates(activeMode) {
            const encodeCard = document.getElementById('card-encode');
            const decodeCard = document.getElementById('card-decode');
            if (!encodeCard || !decodeCard) return;

            // Reset both
            encodeCard.classList.remove('card-active', 'card-dimmed');
            decodeCard.classList.remove('card-active', 'card-dimmed');

            if (activeMode === 'encode') {
                encodeCard.classList.add('card-active');
                decodeCard.classList.add('card-dimmed');
            } else if (activeMode === 'decode') {
                decodeCard.classList.add('card-active');
                encodeCard.classList.add('card-dimmed');
            }
        }

        function handleModeClick(mode) {
            // Check authentication before allowing access
            if (!IS_LOGGED_IN) {
                showToast("You must be logged in to use this feature.");
                window.location.href = 'login.php';
                return;
            }

            const area = document.getElementById("contentArea");

            if (currentMode === mode) {
                area.style.display = "none";
                currentMode = null;
                updateCardStates(null);
                return;
            }

            currentMode = mode;
            renderForm(mode);
            initDragUploads(); // Initialize drag and drop
            setupDynamicListeners(); // Attach listeners to newly created form elements
            area.style.display = "block";
            updateCardStates(mode);

            setTimeout(() => {
                area.scrollIntoView({ behavior: "smooth", block: "start" });
            }, 10);
        }

        function renderForm(mode) {
            const area = document.getElementById("contentArea");
            // Reset globals
            secretFilesArray = [];
            currentCoverImageWidth = 0;
            currentCoverImageHeight = 0;

            if (mode === 'encode') {
                area.innerHTML = `
                    <form class="form-container encode-form">
                        <input type="hidden" name="csrf_token" value="${CSRF_TOKEN}">
                        <h2>Encode Image</h2><br>
                        
                        <div class="input-group" id="group-cover">
                            <label>Upload Cover Image (Image to hide data in)</label>
                            <input type="file" name="cover_image" id="input-cover" accept="image/png, image/jpeg, image/jpg" required>
                            
                            <div class="preview-container" id="preview-cover" style="display: none;">
                                <img src="" class="preview-img">
                                <div class="file-info">
                                    <span class="file-name">filename.png</span>
                                    <span class="file-size">0 KB</span>
                                    <span class="file-dims" style="display:block; font-size:0.8em; color:#aaa;"></span>
                                </div>
                                <button type="button" class="remove-btn" data-input="input-cover" data-preview="preview-cover" data-group="group-cover">×</button>
                            </div>
                        </div>

                        <!-- Capacity Display -->
                        <div id="capacity-display" style="display:none; margin-bottom: 20px; padding: 14px 16px; border-radius: 10px; background: rgba(0, 255, 255, 0.04); border: 1px solid rgba(0, 255, 255, 0.2);">
                            <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                                <span style="color: #ccc; font-size:0.88em; letter-spacing:1px; text-transform:uppercase;">Payload Capacity</span>
                                <span id="capacity-value" style="color: #00ffff; font-weight: bold; font-size:0.88em;"></span>
                            </div>
                            <div style="display: flex; justify-content: space-between; margin-bottom: 10px;">
                                <span style="color: #ccc; font-size:0.88em; letter-spacing:1px; text-transform:uppercase;">Current Usage</span>
                                <span id="usage-value" style="color: #00ff88; font-weight: bold; font-size:0.88em;"></span>
                            </div>

                            <!-- Progress Bar -->
                            <div style="width:100%; height:10px; background: rgba(255,255,255,0.08); border-radius:999px; overflow:hidden; border: 1px solid rgba(255,255,255,0.1); margin-bottom:8px;">
                                <div id="capacity-bar" style="height:100%; width:0%; border-radius:999px; transition: width 0.4s ease, background 0.4s ease; background: #00ff88;"></div>
                            </div>
                            <div style="display:flex; justify-content:space-between; font-size:0.75em; color:rgba(255,255,255,0.35); margin-bottom:6px;">
                                <span>0%</span>
                                <span id="capacity-pct" style="font-weight:bold; color: rgba(0,255,136,0.7);">0%</span>
                                <span>100%</span>
                            </div>

                            <div id="capacity-warning" style="display:none; color: #ff4444; font-size: 0.85em; margin-top: 4px; padding: 6px 10px; background: rgba(255,68,68,0.08); border-radius:6px; border:1px solid rgba(255,68,68,0.3);">
                                <i class="fa-solid fa-triangle-exclamation"></i>&nbsp;Data exceeds image capacity! Remove some files or use a larger image.
                            </div>
                        </div>

                        <div class="input-group" id="group-secret" style="margin-bottom: 15px;">
                            <label>Secret Data (File to hide)</label>
                            <input type="file" name="secret_file" id="input-secret" multiple>

                            <div class="preview-container" id="preview-secret" style="display: none;">
                                <div class="preview-img" style="display:flex; align-items:center; justify-content:center; background:rgba(0,255,255,0.1); color:#00ffff; font-size:24px;">
                                    <i class="fa-solid fa-file"></i>
                                </div>
                                <div class="file-info">
                                    <div class="file-name">secret.txt</div>
                                    <div class="file-size">0 KB</div>
                                </div>
                                <button type="button" class="remove-btn" data-input="input-secret" data-preview="preview-secret" data-group="group-secret">×</button>
                            </div>
                        </div>

                        <div class="input-group" style="margin-bottom: 15px;">
                            <label>LSB Selection Method</label>
                            <div style="display: flex; gap: 20px; align-items: start; margin-top: 10px; flex-wrap: wrap;">
                                <div class="lsb-option" style="position: relative;">
                                    <label style="display: flex; align-items: center; gap: 8px; color: #fff; cursor: pointer;">
                                        <input type="radio" name="lsb_method" value="1" checked style="accent-color: #00ffff;">
                                        Sharing Image
                                        <i class="fa-solid fa-circle-info" style="color: #00ffff; font-size: 0.9em; cursor: pointer;" 
                                           data-tip="tip1"></i>
                                    </label>
                                    <div id="tip1" class="tooltip">
                                        <strong>Sharing Image</strong><br>
                                        • Lower data capacity<br>
                                        • Minimal image distortion<br>
                                        • Suitable for social media/email
                                    </div>
                                </div>
                                
                                <div class="lsb-option" style="position: relative;">
                                    <label style="display: flex; align-items: center; gap: 8px; color: #fff; cursor: pointer;">
                                        <input type="radio" name="lsb_method" value="2" style="accent-color: #00ffff;">
                                        Storing in My Device
                                        <i class="fa-solid fa-circle-info" style="color: #00ffff; font-size: 0.9em; cursor: pointer;" 
                                           data-tip="tip2"></i>
                                    </label>
                                    <div id="tip2" class="tooltip">
                                        <strong>Storing in My Device</strong><br>
                                        • Higher data capacity<br>
                                        • Slightly more visible changes<br>
                                        • Suitable for personal storage
                                    </div>
                                </div>
                            </div>
                        </div>

                        <div class="input-group">
                            <label>Password</label>
                            <div class="input-wrapper">
                                <input type="password" name="password" id="encode-pass" placeholder="Enter password">
                                <i class="fa-solid fa-eye toggle-icon"></i>
                            </div>
                            <div class="validation-feedback" id="encodePasswordRules" style="display:none; flex-direction:column; gap:5px; margin-top:10px; font-size:0.8rem; color:rgba(0, 255, 255, 0.6);">
                                <span id="rule-length">● At least 8 characters</span>
                                <span id="rule-upper">● At least One Uppercase Letter</span>
                                <span id="rule-lower">● At least One Lowercase Letter</span>
                                <span id="rule-number">● At least One Number</span>
                                <span id="rule-special">● At least One Special Symbol</span>
                            </div>
                        </div>
                        <button class="btn-submit" type="submit">Hide Data</button>
                    </form>
                `;
            } else if (mode === 'decode') {
                area.innerHTML = `
                    <form class="form-container decode-form">
                        <input type="hidden" name="csrf_token" value="${CSRF_TOKEN}">
                        <h2>Decode Image</h2>
                        
                        <div class="input-group" id="group-stego">
                            <label>Upload Steganographic Image</label>
                            <input type="file" name="stego_image" id="input-stego" accept="image/png" required>
 
                            <div class="preview-container" id="preview-stego" style="display: none;">
                                <img src="" class="preview-img">
                                <div class="file-info">
                                    <span class="file-name">stego_image.png</span>
                                    <span class="file-size">0 KB</span>
                                </div>
                                <button type="button" class="remove-btn" data-input="input-stego" data-preview="preview-stego" data-group="group-stego">×</button>
                            </div>
                        </div>

                        <div class="input-group">
                            <label>Password</label>
                            <div class="input-wrapper">
                                <input type="password" name="password" id="decode-pass" placeholder="Enter password" required>
                                <i class="fa-solid fa-eye toggle-icon"></i>
                            </div>
                        </div>
                        <button class="btn-submit" type="submit">Reveal Data</button>
                    </form>
                `;
            }
        }

        // ════════════════════════════════════════════════════════════════════════════════
        // GOAL: Guarantee the stego OUTPUT PNG is always < 900KB, even at 100% capacity.
        //
        // WHY PIXEL COUNT (not file size):
        //   Stego output size ≈ W × H × 3 × 0.95 bytes (worst case: all LSBs filled
        //   with encrypted noise, which compresses poorly).
        //   For 300,000 pixels: 300,000 × 3 × 0.95 = 855KB < 900KB ✓
        //   File size alone is unreliable — a solid-color 800KB PNG can be huge in pixels.
        //
        // RESULT: After encode, the stego image the user downloads is always < 900KB.
        //         When they later upload it to decode, it's always under the 1MB nginx limit.
        const MAX_COVER_PIXELS = 300000; // Guarantees stego output < 900KB worst-case

        function compressImageBeforeUpload(file, input, previewId, groupId) {
            const isJPEG = file.type === 'image/jpeg';

            const reader = new FileReader();
            reader.onload = function (e) {
                const img = new Image();
                img.onload = function () {
                    let width  = img.width;
                    let height = img.height;
                    const originalPixels = width * height;

                    // Scale DOWN proportionally to fit within MAX_COVER_PIXELS
                    if (originalPixels > MAX_COVER_PIXELS) {
                        const scale = Math.sqrt(MAX_COVER_PIXELS / originalPixels);
                        width  = Math.floor(width  * scale);
                        height = Math.floor(height * scale);
                        showToast(`Resizing to ${width}×${height}px to keep stego output under 1MB...`, 'info');
                    }

                    const canvas = document.createElement('canvas');
                    canvas.width  = width;
                    canvas.height = height;
                    canvas.getContext('2d').drawImage(img, 0, 0, width, height);

                    // PNG stays PNG (lossless — better quality for cover images).
                    // JPEG stays JPEG (PHP reads pixel values anyway, stego output is always PNG).
                    const mimeType = isJPEG ? 'image/jpeg' : 'image/png';
                    const quality  = isJPEG ? 0.85 : 1.0;

                    canvas.toBlob(function (blob) {
                        const cleanName = file.name.replace(/\.[^.]+$/, '') || 'cover_image';
                        const ext = isJPEG ? '.jpg' : '.png';
                        const compressedFile = new File([blob], cleanName + ext, { type: mimeType });

                        // Replace the file input
                        const dt = new DataTransfer();
                        dt.items.add(compressedFile);
                        input.files = dt.files;

                        const wasResized = originalPixels > MAX_COVER_PIXELS;
                        if (wasResized) {
                            showToast(
                                `✓ Cover ready: ${formatBytes(file.size)} → ${formatBytes(blob.size)} | ${width}×${height}px (stego output will be < 900KB)`,
                                'success'
                            );
                        }

                        // Update preview UI
                        const fileSizeEl = document.querySelector(`#${previewId} .file-size`);
                        const fileNameEl = document.querySelector(`#${previewId} .file-name`);
                        const dimsEl     = document.querySelector(`#${previewId} .file-dims`);
                        const imgEl      = document.querySelector(`#${previewId} img`);

                        if (fileSizeEl) fileSizeEl.textContent = formatBytes(blob.size);
                        if (fileNameEl) fileNameEl.textContent = compressedFile.name;

                        const previewReader = new FileReader();
                        previewReader.onload = (ev) => {
                            if (imgEl) imgEl.src = ev.target.result;
                            const tempImg = new Image();
                            tempImg.onload = () => {
                                currentCoverImageWidth  = tempImg.width;
                                currentCoverImageHeight = tempImg.height;
                                if (dimsEl) dimsEl.textContent = `${tempImg.width} × ${tempImg.height} px`;
                                updateCapacityDisplay();
                            };
                            tempImg.src = ev.target.result;
                        };
                        previewReader.readAsDataURL(compressedFile);

                        const previewContainer = document.getElementById(previewId);
                        const groupContainer   = document.getElementById(groupId);
                        if (previewContainer) previewContainer.style.display = 'flex';
                        if (groupContainer)   groupContainer.classList.add('has-file');

                    }, mimeType, quality);
                };
                img.src = e.target.result;
            };
            reader.readAsDataURL(file);
        }

        function handleFileSelect(input, previewId, groupId) {
            const files = input.files;
            if ((!files || files.length === 0) && input.id !== 'input-secret') return;
            if (input.id === 'input-secret' && (!files || files.length === 0)) return;

            const previewContainer = document.getElementById(previewId);
            const groupContainer = document.getElementById(groupId);

            if (input.id === 'input-secret') {
                let currentCount = secretFilesArray.length;
                let added = 0;
                for (let i = 0; i < files.length; i++) {
                    if (currentCount + added >= 15) {
                        showToast("Maximum of 15 secret files reached. Some files were not added.");
                        break;
                    }
                    secretFilesArray.push(files[i]);
                    added++;
                }
                updateSecretFilesPreview(previewId, groupId, input);
                input.value = '';
                updateCapacityDisplay();
            }
            else {
                previewContainer.style.display = 'flex';
                previewContainer.style.padding = '10px';

                const file = files[0];
                const imgEl = previewContainer.querySelector('.preview-img');
                const nameEl = previewContainer.querySelector('.file-name');
                const sizeEl = previewContainer.querySelector('.file-size');
                const dimsEl = previewContainer.querySelector('.file-dims');

                nameEl.textContent = file.name;
                sizeEl.textContent = formatBytes(file.size);

                nameEl.style.whiteSpace = '';
                nameEl.style.overflow = '';

                if (file.type.startsWith('image/')) {
                    // Compress cover images to bypass 1MB Azure nginx limit
                    // JPEG: converted to smaller JPEG (lossy)
                    // PNG: scaled down but kept as PNG (lossless - preserves steganography)
                    if (input.id === 'input-cover') {
                        compressImageBeforeUpload(file, input, previewId, groupId);
                        return;
                    }

                    const reader = new FileReader();
                    reader.onload = function (e) {
                        if (imgEl.tagName === 'IMG') {
                            imgEl.src = e.target.result;

                            // Load image to get dimensions
                            if (input.id === 'input-cover') {
                                const tempImg = new Image();
                                tempImg.onload = function () {
                                    currentCoverImageWidth = this.width;
                                    currentCoverImageHeight = this.height;
                                    if (dimsEl) dimsEl.textContent = `${this.width} x ${this.height} px`;
                                    updateCapacityDisplay();
                                };
                                tempImg.src = e.target.result;
                            }
                        }
                    };
                    reader.readAsDataURL(file);
                }

                previewContainer.style.display = 'flex';
                groupContainer.classList.add('has-file');
            }
        }

        function updateSecretFilesPreview(previewId, groupId, inputElement) {
            const previewContainer = document.getElementById(previewId);
            const groupContainer = document.getElementById(groupId);

            if (secretFilesArray.length > 0) {
                inputElement.removeAttribute('required');
                groupContainer.classList.add('has-file');
                previewContainer.style.display = 'block';
            } else {
                inputElement.setAttribute('required', 'required');
                groupContainer.classList.remove('has-file');
                previewContainer.style.display = 'none';
                updateCapacityDisplay(); // Ensure progress bar updates when all files are removed
                return;
            }

            previewContainer.innerHTML = '';
            previewContainer.style.display = 'block';
            previewContainer.style.padding = '15px';

            const listDiv = document.createElement('div');
            listDiv.style.display = 'flex';
            listDiv.style.flexDirection = 'column';
            listDiv.style.gap = '8px';
            listDiv.style.maxHeight = '200px';
            listDiv.style.overflowY = 'auto';
            listDiv.style.marginBottom = '15px';

            let totalSize = 0;

            secretFilesArray.forEach((f, index) => {
                totalSize += f.size;
                const item = document.createElement('div');
                item.className = 'file-list-item';
                item.style.background = 'rgba(255, 255, 255, 0.08)';
                item.style.padding = '10px';
                item.style.borderRadius = '6px';
                item.style.display = 'flex';
                item.style.justifyContent = 'space-between';
                item.style.alignItems = 'center';
                item.style.border = '1px solid rgba(0, 255, 255, 0.1)';

                item.innerHTML = `
                    <div style="display:flex; align-items:center; gap:12px; overflow:hidden;">
                        <i class="fa-solid fa-file-code" style="color:#00ffff; font-size:1.1em;"></i>
                        <span style="font-size:0.95em; color: #e0e0e0; white-space:nowrap; overflow:hidden; text-overflow:ellipsis; max-width:180px;">${f.name}</span>
                    </div>
                    <div style="display:flex; align-items:center; gap:10px;">
                        <span style="font-size:0.85em; color:rgba(0, 255, 255, 0.7); white-space:nowrap;">${formatBytes(f.size)}</span>
                        <button type="button" class="single-remove-btn" style="background:none; border:none; color:#ff4444; cursor:pointer;">
                            <i class="fa-solid fa-xmark"></i>
                        </button>
                    </div>
                `;

                const removeBtn = item.querySelector('.single-remove-btn');
                removeBtn.onclick = () => removeSingleFile(index, previewId, groupId, inputElement);

                listDiv.appendChild(item);
            });

            const totalDiv = document.createElement('div');
            totalDiv.style.borderTop = '1px solid rgba(0, 255, 255, 0.3)';
            totalDiv.style.paddingTop = '12px';
            totalDiv.style.marginTop = '5px';
            totalDiv.style.display = 'flex';
            totalDiv.style.justifyContent = 'space-between';
            totalDiv.style.alignItems = 'center';
            totalDiv.style.fontWeight = 'bold';

            totalDiv.innerHTML = `
                <span style="color: #fff; text-transform:uppercase; letter-spacing:1px; font-size:0.9em;">Total Selection Size</span>
                <span style="color: #00ff88; font-size:1.1em;">${formatBytes(totalSize)}</span>
            `;

            previewContainer.appendChild(listDiv);
            previewContainer.appendChild(totalDiv);

            updateCapacityDisplay();
        }

        function removeSingleFile(index, previewId, groupId, inputElement) {
            secretFilesArray.splice(index, 1);
            updateSecretFilesPreview(previewId, groupId, inputElement);
        }

        function removeFile(inputId, previewId, groupId) {
            const input = document.getElementById(inputId);
            const previewContainer = document.getElementById(previewId);
            const groupContainer = document.getElementById(groupId);

            input.value = '';

            if (groupId === 'group-secret') {
                secretFilesArray = [];
                input.setAttribute('required', 'required');
                updateCapacityDisplay();
            }
            if (groupId === 'group-cover') {
                currentCoverImageWidth = 0;
                currentCoverImageHeight = 0;
                updateCapacityDisplay();
            }

            previewContainer.style.display = 'none';
            groupContainer.classList.remove('has-file');
        }

        function updateCapacityDisplay() {
            const displayEl = document.getElementById('capacity-display');
            if (!displayEl) return;

            // Only show if we have an image
            if (currentCoverImageWidth === 0 || currentCoverImageHeight === 0) {
                displayEl.style.display = 'none';
                return;
            }

            displayEl.style.display = 'block';

            // Calculate Capacity
            const totalPixels = currentCoverImageWidth * currentCoverImageHeight;

            // 1. Subtract Header Capacity (33 bytes stored in LSB1)
            // Header is always LSB1 (3 bits per pixel)
            const headerBytes = 33;
            const headerPixels = Math.ceil((headerBytes * 8) / 3); // ~102 pixels

            const availablePixels = totalPixels - headerPixels;

            let maxCapacity = 0;
            if (availablePixels > 0) {
                const lsbMode = parseInt(document.querySelector('input[name="lsb_method"]:checked').value);
                const maxBodyBits = availablePixels * 3 * lsbMode;
                const maxBodyBytes = Math.floor(maxBodyBits / 8);

                // 2. Subtract Auth Tag (16 bytes)
                maxCapacity = maxBodyBytes - 16;
            }

            if (maxCapacity < 0) maxCapacity = 0;

            document.getElementById('capacity-value').textContent = formatBytes(maxCapacity);

            // Calculate Usage
            let currentUsage = 0;
            secretFilesArray.forEach(f => {
                currentUsage += f.size;
            });

            document.getElementById('usage-value').textContent = formatBytes(currentUsage);

            // --- Progress Bar ---
            const barEl = document.getElementById('capacity-bar');
            const pctEl = document.getElementById('capacity-pct');
            const warningEl = document.getElementById('capacity-warning');
            const submitBtn = document.querySelector('.btn-submit');

            const pct = maxCapacity > 0 ? Math.min((currentUsage / maxCapacity) * 100, 100) : (currentUsage > 0 ? 100 : 0);
            const displayPct = Math.round(pct);

            if (barEl) {
                barEl.style.width = pct + '%';

                // Color: green → yellow → orange → red
                let barColor;
                if (pct < 60) {
                    barColor = '#00ff88';
                } else if (pct < 80) {
                    const t = (pct - 60) / 20;
                    const r = Math.round(0 + t * 255);
                    const g = Math.round(255 + t * (220 - 255));
                    barColor = `rgb(${r}, ${g}, 0)`;
                } else if (pct < 100) {
                    const t = (pct - 80) / 20;
                    const r = 255;
                    const g = Math.round(220 - t * 220);
                    barColor = `rgb(${r}, ${g}, 0)`;
                } else {
                    barColor = '#ff4444';
                }
                barEl.style.background = barColor;
            }

            if (pctEl) {
                pctEl.textContent = displayPct + '%';
                pctEl.style.color = pct >= 100 ? '#ff4444' : (pct >= 80 ? '#ffaa00' : 'rgba(0,255,136,0.7)');
            }

            if (currentUsage > maxCapacity && maxCapacity > 0) {
                document.getElementById('usage-value').style.color = '#ff4444';
                if (warningEl) warningEl.style.display = 'block';
                if (submitBtn) {
                    submitBtn.disabled = true;
                    submitBtn.style.opacity = '0.45';
                    submitBtn.style.cursor = 'not-allowed';
                    submitBtn.title = 'Cannot hide data: payload exceeds image capacity.';
                }
            } else {
                document.getElementById('usage-value').style.color = pct >= 80 ? '#ffaa00' : '#00ff88';
                if (warningEl) warningEl.style.display = 'none';
                if (submitBtn) {
                    submitBtn.disabled = false;
                    submitBtn.style.opacity = '';
                    submitBtn.style.cursor = '';
                    submitBtn.title = '';
                }
            }
        }

        function formatBytes(bytes, decimals = 2) {
            if (!+bytes) return '0 Bytes';
            const k = 1024;
            const dm = decimals < 0 ? 0 : decimals;
            const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
            const i = Math.floor(Math.log(bytes) / Math.log(k));
            return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
        }

        function toggleTooltip(e, id) {
            e.preventDefault();
            e.stopPropagation(); // Stop label from toggling radio

            const tip = document.getElementById(id);
            const isVisible = (tip.style.display === 'block');

            // Hide all tooltips first
            document.querySelectorAll('.tooltip').forEach(t => t.style.display = 'none');

            // Toggle current one
            if (!isVisible) {
                tip.style.display = 'block';
            }
        }

        // Close tooltips on click outside
        document.addEventListener('click', () => {
            document.querySelectorAll('.tooltip').forEach(t => t.style.display = 'none');
        });


        // Drag and Drop Logic
        function initDragUploads() {
            const dropZones = document.querySelectorAll('.input-group');

            dropZones.forEach(zone => {
                const input = zone.querySelector('input[type="file"]');
                if (!input) return;

                zone.addEventListener('dragover', (e) => {
                    e.preventDefault();
                    zone.classList.add('drag-over');
                });

                zone.addEventListener('dragleave', (e) => {
                    e.preventDefault();
                    zone.classList.remove('drag-over');
                });

                zone.addEventListener('drop', (e) => {
                    e.preventDefault();
                    zone.classList.remove('drag-over');

                    if (e.dataTransfer.files.length > 0) {
                        // Validate file type against the input's accept attribute
                        if (input.accept) {
                            const accepted = input.accept.split(',').map(t => t.trim().toLowerCase());
                            const droppedFile = e.dataTransfer.files[0];
                            const mimeType = droppedFile.type.toLowerCase();
                            const fileName = droppedFile.name.toLowerCase();
                            const typeOk = accepted.some(a => {
                                if (a.startsWith('image/') || a.startsWith('application/'))
                                    return mimeType === a;
                                if (a.startsWith('.'))
                                    return fileName.endsWith(a);
                                return false;
                            });
                            if (!typeOk) {
                                showToast('Invalid file type. Accepted types: ' + input.accept);
                                return;
                            }
                        }

                        // Assign files to input
                        input.files = e.dataTransfer.files;

                        // Trigger existing selection handler
                        let previewId, groupId;
                        if (input.id === 'input-cover') { previewId = 'preview-cover'; groupId = 'group-cover'; }
                        else if (input.id === 'input-secret') { previewId = 'preview-secret'; groupId = 'group-secret'; }
                        else if (input.id === 'input-stego') { previewId = 'preview-stego'; groupId = 'group-stego'; }

                        handleFileSelect(input, previewId, groupId);
                    }
                });
            });
        }

        // Password Validation Logic for Encode
        function showEncodePasswordRules() {
            const rules = document.getElementById('encodePasswordRules');
            if (rules) rules.style.display = 'flex';
        }

        function hideEncodePasswordRules() {
            const rules = document.getElementById('encodePasswordRules');
            const passInput = document.getElementById('encode-pass');
            // Prevent rules from hiding and causing a layout shift if the user has typed something
            if (passInput && passInput.value.length > 0) return;
            if (rules) rules.style.display = 'none';
        }


        function validateEncodePassword() {
            const passInput = document.getElementById('encode-pass');
            if (!passInput) return false;

            const val = passInput.value;
            const rules = {
                length: { el: document.getElementById('rule-length'), regex: /.{8,}/, text: "At least 8 characters" },
                upper: { el: document.getElementById('rule-upper'), regex: /[A-Z]/, text: "At least One Uppercase Letter" },
                lower: { el: document.getElementById('rule-lower'), regex: /[a-z]/, text: "At least One Lowercase Letter" },
                number: { el: document.getElementById('rule-number'), regex: /[0-9]/, text: "At least One Number" },
                special: { el: document.getElementById('rule-special'), regex: /[\W_]/, text: "At least One Special Symbol" }
            };

            // Auto-show if typing happens (in case it was hidden)
            if (val.length > 0) showEncodePasswordRules();

            let allValid = true;

            for (const key in rules) {
                const rule = rules[key];
                if (!rule.el) continue;

                if (rule.regex.test(val)) {
                    rule.el.style.color = '#00ff88';
                    rule.el.innerHTML = '<i class="fa-solid fa-check"></i> ' + rule.text;
                } else {
                    rule.el.style.color = 'rgba(255, 68, 68, 0.8)';
                    rule.el.innerHTML = '● ' + rule.text;
                    allValid = false;
                }
            }
            return allValid;
        }

        async function submitEncode(event) {
            event.preventDefault();

            // Validate Password Rules First
            if (!validateEncodePassword()) {
                showToast("Password does not meet security requirements.");
                document.getElementById('encode-pass').focus();
                showEncodePasswordRules();
                return;
            }

            const coverInput = document.getElementById('input-cover');
            if (coverInput.files.length === 0) {
                showToast("Please select a cover image (PNG or JPEG).");
                return;
            }

            if (secretFilesArray.length === 0) {
                showToast("Please select at least one secret file.");
                return;
            }

            if (secretFilesArray.length > 15) {
                showToast("You can only hide a maximum of 15 secret files at once. Please remove some files.");
                return;
            }

            const passInput = document.getElementById('encode-pass');
            if (!passInput.value) {
                showToast("Please enter a password.");
                return;
            }

            const formData = new FormData();
            formData.append('csrf_token', CSRF_TOKEN);
            formData.append('cover_image', coverInput.files[0]);

            secretFilesArray.forEach(file => {
                formData.append('secret_files[]', file);
            });

            // Get selected LSB method
            const lsb = document.querySelector('input[name="lsb_method"]:checked').value;
            formData.append('lsb_method', lsb);
            formData.append('password', passInput.value);

            try {
                showLoader('encode');

                // Disable all form inputs during process
                event.target.querySelectorAll('input, button').forEach(el => el.disabled = true);

                const response = await fetch('process_encode.php', {
                    method: 'POST',
                    body: formData,
                    credentials: 'include'
                });

                if (response.ok) {
                    const blob = await response.blob();
                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = "stego_image.png";
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(url);
                    showToast("Encoding successful! Image downloaded.", "success");

                    // Reset form
                    event.target.reset();
                    secretFilesArray = [];
                    currentCoverImageWidth = 0;
                    currentCoverImageHeight = 0;

                    const previewCover = document.getElementById('preview-cover');
                    if (previewCover) previewCover.style.display = 'none';
                    const groupCover = document.getElementById('group-cover');
                    if (groupCover) groupCover.classList.remove('has-file');

                    const previewSecret = document.getElementById('preview-secret');
                    if (previewSecret) previewSecret.style.display = 'none';
                    const groupSecret = document.getElementById('group-secret');
                    if (groupSecret) groupSecret.classList.remove('has-file');
                    const inputSecret = document.getElementById('input-secret');
                    if (inputSecret) inputSecret.setAttribute('required', 'required');

                    // Reset password rule indicators back to neutral state
                    const rulesPanel = document.getElementById('encodePasswordRules');
                    if (rulesPanel) {
                        rulesPanel.style.display = 'none';
                        const ruleTexts = {
                            'rule-length': 'At least 8 characters',
                            'rule-upper': 'At least One Uppercase Letter',
                            'rule-lower': 'At least One Lowercase Letter',
                            'rule-number': 'At least One Number',
                            'rule-special': 'At least One Special Symbol'
                        };
                        for (const [id, text] of Object.entries(ruleTexts)) {
                            const el = document.getElementById(id);
                            if (el) {
                                el.style.color = 'rgba(0, 255, 255, 0.6)';
                                el.innerHTML = '● ' + text;
                            }
                        }
                    }

                    updateCapacityDisplay();
                } else {
                    const text = await response.text();
                    showToast("Error: " + text);
                }

                event.target.querySelectorAll('input, button').forEach(el => el.disabled = false);
                hideLoader();

            } catch (e) {
                hideLoader();
                showToast("Network error: " + e.message);
                event.target.querySelectorAll('input, button').forEach(el => el.disabled = false);
            }
        }


        function setupDynamicListeners() {
            // Forms
            const encodeForm = document.querySelector('.encode-form');
            if (encodeForm) encodeForm.addEventListener('submit', submitEncode);
            const decodeForm = document.querySelector('.decode-form');
            if (decodeForm) decodeForm.addEventListener('submit', submitDecode);

            // Encode password interactivity
            const encodePass = document.getElementById('encode-pass');
            if (encodePass) {
                encodePass.addEventListener('input', validateEncodePassword);
                encodePass.addEventListener('focus', showEncodePasswordRules);
                encodePass.addEventListener('blur', hideEncodePasswordRules);
            }

            // Info Tooltips
            document.querySelectorAll('.fa-circle-info').forEach(icon => {
                icon.addEventListener('click', (e) => {
                    toggleTooltip(e, icon.dataset.tip);
                });
            });

            // LSB Method update
            document.querySelectorAll('input[name="lsb_method"]').forEach(radio => {
                radio.addEventListener('change', updateCapacityDisplay);
            });

            // File selectors
            const inputCover = document.getElementById('input-cover');
            if (inputCover) {
                inputCover.addEventListener('change', () => handleFileSelect(inputCover, 'preview-cover', 'group-cover'));
            }
            const inputSecret = document.getElementById('input-secret');
            if (inputSecret) {
                inputSecret.addEventListener('change', () => handleFileSelect(inputSecret, 'preview-secret', 'group-secret'));
            }
            const inputStego = document.getElementById('input-stego');
            if (inputStego) {
                inputStego.addEventListener('change', () => handleFileSelect(inputStego, 'preview-stego', 'group-stego'));
            }

            // Remove buttons
            document.querySelectorAll('.remove-btn').forEach(btn => {
                btn.addEventListener('click', () => {
                    removeFile(btn.dataset.input, btn.dataset.preview, btn.dataset.group);
                });
            });
        }


        async function submitDecode(event) {
            event.preventDefault();

            // Disable all form inputs during process
            event.target.querySelectorAll('input, button').forEach(el => el.disabled = true);
            showLoader('decode');

            const formData = new FormData();
            formData.append('csrf_token', CSRF_TOKEN);

            const stegoInput = document.getElementById('input-stego');
            if (stegoInput.files.length > 0) {
                formData.append('stego_image', stegoInput.files[0]);
            }

            const pass = document.getElementById('decode-pass').value;
            formData.append('password', pass);

            try {
                const response = await fetch('process_decode.php', { method: 'POST', body: formData, credentials: 'include' });
                if (response.ok) {
                    const blob = await response.blob();

                    // Encoding ALWAYS creates a ZIP archive, so decoded output is always a ZIP.
                    const filename = 'secret.zip';

                    const url = window.URL.createObjectURL(blob);
                    const a = document.createElement('a');
                    a.href = url;
                    a.download = filename;
                    document.body.appendChild(a);
                    a.click();
                    a.remove();
                    window.URL.revokeObjectURL(url);
                    showToast("Decoding successful! Your file has been saved as secret.zip — extract it to get your original file(s).", "success");

                    // Reset form
                    event.target.reset();
                    const previewStego = document.getElementById('preview-stego');
                    if (previewStego) previewStego.style.display = 'none';
                    const groupStego = document.getElementById('group-stego');
                    if (groupStego) groupStego.classList.remove('has-file');
                } else {
                    const text = await response.text();
                    showToast("Error: " + text);
                }
            } finally {
                event.target.querySelectorAll('input, button').forEach(el => el.disabled = false);
                hideLoader();
            }
        }
    </script>
</body>

</html>
