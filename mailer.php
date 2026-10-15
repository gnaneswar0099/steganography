<?php
// ===== mailer.php =====
declare(strict_types=1);

// Prevent direct access
if (basename(__FILE__) === basename($_SERVER['SCRIPT_FILENAME'])) {
    http_response_code(403);
    exit('Forbidden');
}

require_once __DIR__ . '/app_config.php';

use PHPMailer\PHPMailer\PHPMailer;
use PHPMailer\PHPMailer\Exception as PHPMailerException;

/**
 * Send a system transactional email using configured provider.
 *
 * Supported providers (MAIL_PROVIDER env var):
 *  - 'brevo' : HTTPS cURL API (default on Render free tier, bypasses SMTP port blocks)
 *  - 'smtp'  : PHPMailer SMTP (local development)
 *  - 'log'   : Logs message to server error_log (ONLY permitted when APP_ENV=local)
 *
 * @param string $toEmail Recipient email address
 * @param string $subject Email subject line
 * @param string $htmlBody HTML content
 * @param string $textBody Plain text fallback (optional)
 * @return bool True if accepted by provider, false on failure (never throws)
 */
function send_system_email(string $toEmail, string $subject, string $htmlBody, string $textBody = ''): bool
{
    $_env = file_exists(__DIR__ . '/.env') ? (parse_ini_file(__DIR__ . '/.env') ?: []) : [];

    $provider = strtolower(app_env('MAIL_PROVIDER', $_env, 'brevo') ?? 'brevo');
    $appEnv   = strtolower(app_env('APP_ENV', $_env, 'production') ?? 'production');
    $fromMail = app_env('MAIL_FROM', $_env, 'no-reply@localhost') ?? 'no-reply@localhost';
    $fromName = app_env('MAIL_FROM_NAME', $_env, 'Steganography Security') ?? 'Steganography Security';

    if (empty($textBody)) {
        $textBody = strip_tags($htmlBody);
    }

    // ----------------------------------------------------------------------
    // 1. BREVO PROVIDER (HTTPS REST API over port 443)
    // ----------------------------------------------------------------------
    if ($provider === 'brevo') {
        $apiKey = app_env('BREVO_API_KEY', $_env, '');
        if (empty($apiKey)) {
            error_log('Mailer error: BREVO_API_KEY is not configured.');
            return false;
        }

        $url = 'https://api.brevo.com/v3/smtp/email';
        $payload = [
            'sender'      => ['name' => $fromName, 'email' => $fromMail],
            'to'          => [['email' => $toEmail]],
            'subject'     => $subject,
            'htmlContent' => $htmlBody,
            'textContent' => $textBody,
        ];

        $ch = curl_init($url);
        if ($ch === false) {
            error_log('Mailer error: curl_init failed.');
            return false;
        }

        curl_setopt_array($ch, [
            CURLOPT_POST           => true,
            CURLOPT_POSTFIELDS     => json_encode($payload),
            CURLOPT_HTTPHEADER     => [
                'accept: application/json',
                'api-key: ' . $apiKey,
                'content-type: application/json',
            ],
            CURLOPT_RETURNTRANSFER => true,
            CURLOPT_CONNECTTIMEOUT => 5,   // Resilience: fast fail (5s)
            CURLOPT_TIMEOUT        => 10,  // Resilience: total timeout (10s)
            CURLOPT_SSL_VERIFYPEER => true,
            CURLOPT_SSL_VERIFYHOST => 2,
        ]);

        $response = curl_exec($ch);
        $httpCode = curl_getinfo($ch, CURLINFO_HTTP_CODE);
        $curlErr  = curl_error($ch);
        curl_close($ch);

        if ($curlErr !== '') {
            error_log('Mailer error: Brevo request failed.');
            return false;
        }

        // Brevo returns 201 Created on success
        if ($httpCode >= 200 && $httpCode < 300) {
            return true;
        }

        error_log("Mailer error: Brevo API returned HTTP {$httpCode}.");
        return false;
    }

    // ----------------------------------------------------------------------
    // 2. SMTP PROVIDER (PHPMailer for local dev)
    // ----------------------------------------------------------------------
    if ($provider === 'smtp') {
        if (!class_exists(PHPMailer::class)) {
            $autoload = __DIR__ . '/vendor/autoload.php';
            if (file_exists($autoload)) {
                require_once $autoload;
            }
        }

        if (!class_exists(PHPMailer::class)) {
            error_log('Mailer error: PHPMailer class not available.');
            return false;
        }

        try {
            $mail = new PHPMailer(true);
            $mail->Timeout = 10;
            $mail->isSMTP();
            $mail->Host       = app_env('SMTP_HOST', $_env, 'localhost') ?? 'localhost';
            $mail->SMTPAuth   = true;
            $mail->Username   = app_env('SMTP_USER', $_env, '') ?? '';
            $mail->Password   = app_env('SMTP_PASS', $_env, '') ?? '';
            $mail->Port       = (int) (app_env('SMTP_PORT', $_env, '587') ?? 587);
            $mail->SMTPSecure = ($mail->Port === 465) ? PHPMailer::ENCRYPTION_SMTPS : PHPMailer::ENCRYPTION_STARTTLS;

            $mail->setFrom($fromMail, $fromName);
            $mail->addAddress($toEmail);
            $mail->isHTML(true);
            $mail->Subject = $subject;
            $mail->Body    = $htmlBody;
            $mail->AltBody = $textBody;

            return $mail->send();
        } catch (PHPMailerException $e) {
            error_log('Mailer error: SMTP delivery failed.');
            return false;
        } catch (Throwable $t) {
            error_log('Mailer error: SMTP delivery failed.');
            return false;
        }
    }

    // ----------------------------------------------------------------------
    // 3. LOG PROVIDER (Only permitted when APP_ENV=local)
    // ----------------------------------------------------------------------
    if ($provider === 'log') {
        if ($appEnv !== 'local') {
            error_log('Mailer security warning: Provider "log" is only permitted when APP_ENV=local.');
            return false;
        }

        error_log(sprintf(
            "[LOCAL_MAIL_LOG] To: %s | Subject: %s | Body: %s",
            $toEmail,
            $subject,
            substr($textBody, 0, 500)
        ));
        return true;
    }

    error_log('Mailer error: MAIL_PROVIDER is unavailable.');
    return false;
}
