<?php
declare(strict_types=1);

// Determine what kind of error to display
$errorCode = $_GET['code'] ?? '404';
$errorCode = in_array($errorCode, ['400', '403', '404', '405', '500', '503'], true) ? $errorCode : '404';

$errorMessages = [
    '400' => ['title' => 'BAD REQUEST', 'msg' => 'The request could not be understood by the server.'],
    '403' => ['title' => 'ACCESS DENIED', 'msg' => 'You do not have permission to access this resource.'],
    '404' => ['title' => 'NOT FOUND', 'msg' => 'The requested file or resource does not exist.'],
    '405' => ['title' => 'METHOD NOT ALLOWED', 'msg' => 'The HTTP method used is not permitted for this endpoint.'],
    '500' => ['title' => 'SYSTEM FAILURE', 'msg' => 'An internal server error occurred. Please try again later.'],
    '503' => ['title' => 'SERVICE UNAVAILABLE', 'msg' => 'The server is temporarily unable to handle requests.'],
];

$info = $errorMessages[$errorCode];
http_response_code((int) $errorCode);
?>
<!DOCTYPE html>
<html lang="en">

<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Error
        <?php echo htmlspecialchars($errorCode); ?> —
        <?php echo htmlspecialchars($info['title']); ?>
    </title>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.2/css/all.min.css"
        integrity="sha512-z3gLpd7yknf1YoNbCzqRKc4qyor8gaKU1qmn+CShxbuBusANI9QpRohGBreCFkKxLhei6S9CQXFEbbKuqLg0DA=="
        crossorigin="anonymous" referrerpolicy="no-referrer" />
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }

        body {
            font-family: 'Courier New', monospace;
            background: #0a0e27;
            display: flex;
            justify-content: center;
            align-items: center;
            min-height: 100vh;
            overflow: hidden;
            position: relative;
            color: #fff;
        }

        /* Animated grid background */
        .grid-container {
            position: fixed;
            width: 100%;
            height: 100%;
            overflow: hidden;
            z-index: 0;
            pointer-events: none;
        }

        .grid-canvas {
            position: absolute;
            inset: 0;
            background-image:
                linear-gradient(rgba(0, 255, 255, 0.07) 1px, transparent 1px),
                linear-gradient(90deg, rgba(0, 255, 255, 0.07) 1px, transparent 1px);
            background-size: 40px 40px;
            animation: gridScroll 20s linear infinite;
        }

        @keyframes gridScroll {
            from {
                transform: translateY(0);
            }

            to {
                transform: translateY(40px);
            }
        }

        /* Error card */
        .error-card {
            position: relative;
            z-index: 10;
            width: 560px;
            max-width: 95vw;
            background: rgba(10, 14, 39, 0.88);
            border: 2px solid rgba(0, 255, 255, 0.35);
            border-radius: 20px;
            padding: 50px 40px 40px;
            box-shadow: 0 0 60px rgba(0, 255, 255, 0.2), 0 0 120px rgba(0, 255, 255, 0.05);
            backdrop-filter: blur(12px);
            text-align: center;
            animation: cardIn 0.6s cubic-bezier(0.22, 1, 0.36, 1) both;
        }

        @keyframes cardIn {
            from {
                opacity: 0;
                transform: translateY(30px) scale(0.96);
            }

            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }

        /* Corner brackets */
        .corner {
            position: absolute;
            width: 22px;
            height: 22px;
            border: 2px solid #00ffff;
        }

        .corner.tl {
            top: 12px;
            left: 12px;
            border-right: none;
            border-bottom: none;
        }

        .corner.tr {
            top: 12px;
            right: 12px;
            border-left: none;
            border-bottom: none;
        }

        .corner.bl {
            bottom: 12px;
            left: 12px;
            border-right: none;
            border-top: none;
        }

        .corner.br {
            bottom: 12px;
            right: 12px;
            border-left: none;
            border-top: none;
        }

        /* Scan line */
        .scan-line {
            position: absolute;
            top: 0;
            left: 0;
            width: 100%;
            height: 2px;
            background: linear-gradient(90deg, transparent, #00ffff, transparent);
            animation: scan 2.5s linear infinite;
        }

        @keyframes scan {
            0% {
                top: 0;
                opacity: 1;
            }

            100% {
                top: 100%;
                opacity: 0;
            }
        }

        /* Error code */
        .error-code {
            font-size: clamp(72px, 15vw, 110px);
            font-weight: 900;
            color: #00ffff;
            letter-spacing: 8px;
            text-shadow: 0 0 30px rgba(0, 255, 255, 0.6), 0 0 60px rgba(0, 255, 255, 0.3);
            animation: codeGlitch 6s infinite;
            line-height: 1;
            margin-bottom: 10px;
        }

        @keyframes codeGlitch {

            0%,
            88%,
            100% {
                transform: translate(0);
                text-shadow: 0 0 30px rgba(0, 255, 255, 0.6);
            }

            89% {
                transform: translate(-3px, 2px);
                color: #ff4444;
            }

            90% {
                transform: translate(3px, -2px);
                color: #00ffff;
            }

            91% {
                transform: translate(-2px, -2px);
            }

            92% {
                transform: translate(2px, 2px);
            }

            93% {
                transform: translate(0);
            }
        }

        .error-title {
            font-size: 1.3rem;
            letter-spacing: 4px;
            color: #ff4444;
            text-transform: uppercase;
            margin-bottom: 20px;
            text-shadow: 0 0 12px rgba(255, 68, 68, 0.5);
        }

        .error-divider {
            width: 60%;
            height: 1px;
            background: linear-gradient(90deg, transparent, rgba(0, 255, 255, 0.4), transparent);
            margin: 20px auto;
        }

        .error-message {
            color: rgba(0, 255, 255, 0.75);
            font-size: 0.95rem;
            line-height: 1.7;
            letter-spacing: 0.5px;
            margin-bottom: 35px;
        }

        /* Status row */
        .status-row {
            display: flex;
            justify-content: center;
            gap: 25px;
            margin-bottom: 35px;
            font-size: 0.78rem;
            letter-spacing: 1px;
            color: rgba(0, 255, 255, 0.5);
        }

        .status-row span {
            display: flex;
            align-items: center;
            gap: 6px;
        }

        .status-dot {
            width: 7px;
            height: 7px;
            border-radius: 50%;
            background: #ff4444;
            box-shadow: 0 0 8px #ff4444;
            animation: dotPulse 1.5s ease-in-out infinite;
        }

        .status-dot.ok {
            background: #00ff88;
            box-shadow: 0 0 8px #00ff88;
        }

        @keyframes dotPulse {

            0%,
            100% {
                transform: scale(1);
                opacity: 1;
            }

            50% {
                transform: scale(1.4);
                opacity: 0.7;
            }
        }

        /* Buttons */
        .btn-group {
            display: flex;
            gap: 15px;
            justify-content: center;
            flex-wrap: wrap;
        }

        .btn {
            padding: 12px 28px;
            border-radius: 10px;
            font-family: 'Courier New', monospace;
            font-size: 0.9rem;
            font-weight: bold;
            text-transform: uppercase;
            letter-spacing: 2px;
            cursor: pointer;
            transition: all 0.3s ease;
            text-decoration: none;
            display: inline-flex;
            align-items: center;
            gap: 8px;
        }

        .btn-primary {
            background: linear-gradient(135deg, rgba(0, 255, 255, 0.15), rgba(0, 255, 136, 0.15));
            border: 2px solid #00ffff;
            color: #00ffff;
        }

        .btn-primary:hover {
            background: linear-gradient(135deg, rgba(0, 255, 255, 0.3), rgba(0, 255, 136, 0.3));
            box-shadow: 0 0 25px rgba(0, 255, 255, 0.4);
            transform: translateY(-2px);
            color: #fff;
        }

        .btn-secondary {
            background: transparent;
            border: 1px solid rgba(0, 255, 255, 0.3);
            color: rgba(0, 255, 255, 0.7);
        }

        .btn-secondary:hover {
            border-color: rgba(0, 255, 255, 0.7);
            color: #00ffff;
            background: rgba(0, 255, 255, 0.05);
        }

        .footer-note {
            margin-top: 30px;
            font-size: 0.72rem;
            color: rgba(0, 255, 255, 0.3);
            letter-spacing: 2px;
            text-transform: uppercase;
        }
    </style>
</head>

<body>

    <div class="grid-container">
        <div class="grid-canvas"></div>
    </div>

    <div class="error-card">
        <div class="scan-line"></div>
        <div class="corner tl"></div>
        <div class="corner tr"></div>
        <div class="corner bl"></div>
        <div class="corner br"></div>

        <div class="error-code">
            <?php echo htmlspecialchars($errorCode); ?>
        </div>
        <div class="error-title">
            <i class="fa-solid fa-triangle-exclamation"></i>
            &nbsp;
            <?php echo htmlspecialchars($info['title']); ?>
        </div>

        <div class="error-divider"></div>

        <p class="error-message">
            <?php echo htmlspecialchars($info['msg']); ?>
        </p>

        <div class="status-row">
            <span><span class="status-dot"></span> Error Code:
                <?php echo htmlspecialchars($errorCode); ?>
            </span>
            <span><span class="status-dot ok"></span> System Online</span>
            <span><span class="status-dot ok"></span> DB Active</span>
        </div>

        <div class="btn-group">
            <a href="home.php" class="btn btn-primary">
                <i class="fa-solid fa-house"></i> Return Home
            </a>
            <a href="javascript:history.back()" class="btn btn-secondary">
                <i class="fa-solid fa-arrow-left"></i> Go Back
            </a>
        </div>

        <div class="footer-note">Steganography System &nbsp;|&nbsp; Error
            <?php echo htmlspecialchars($errorCode); ?>
        </div>
    </div>

    <script>
        // Add subtle floating particles
        (function () {
            const canvas = document.createElement('canvas');
            canvas.style.cssText = 'position:fixed;top:0;left:0;pointer-events:none;z-index:1;opacity:0.4;';
            document.body.prepend(canvas);

            const ctx = canvas.getContext('2d');
            canvas.width = window.innerWidth;
            canvas.height = window.innerHeight;

            const dots = Array.from({ length: 30 }, () => ({
                x: Math.random() * canvas.width,
                y: Math.random() * canvas.height,
                r: Math.random() * 1.5 + 0.5,
                vx: (Math.random() - 0.5) * 0.4,
                vy: (Math.random() - 0.5) * 0.4,
            }));

            function draw() {
                ctx.clearRect(0, 0, canvas.width, canvas.height);
                dots.forEach(d => {
                    d.x += d.vx; d.y += d.vy;
                    if (d.x < 0) d.x = canvas.width;
                    if (d.x > canvas.width) d.x = 0;
                    if (d.y < 0) d.y = canvas.height;
                    if (d.y > canvas.height) d.y = 0;
                    ctx.beginPath();
                    ctx.arc(d.x, d.y, d.r, 0, Math.PI * 2);
                    ctx.fillStyle = '#00ffff';
                    ctx.fill();
                });
                requestAnimationFrame(draw);
            }
            draw();

            window.addEventListener('resize', () => {
                canvas.width = window.innerWidth;
                canvas.height = window.innerHeight;
            });
        })();
    </script>

</body>

</html>