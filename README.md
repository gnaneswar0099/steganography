# 🔐 Steganography — Technical Documentation

> **Hide encrypted files inside ordinary images using AES-256-GCM + zlib compression + LSB Steganography.**

---

## 📑 Table of Contents
1. [Overview](#overview)
2. [System Architecture](#system-architecture)
3. [Cryptographic Pipeline](#cryptographic-pipeline)
4. [Steganographic Engine](#steganographic-engine)
5. [Multi-File Support](#multi-file-support)
6. [Security Design](#security-design)
7. [File Structure](#file-structure)
8. [Requirements](#requirements)

---

## Overview

This project provides a web-based steganography tool that allows authenticated users to:
- **Encode**: Hide one or more secret files inside a cover image (PNG/JPEG), secured with a password.
- **Decode**: Extract and decrypt hidden files from a steganographic PNG image.

The system layers **strong cryptography** on top of **LSB steganography**, so even if someone extracts the raw LSBs, they only get encrypted ciphertext — not the original data.

---

## System Architecture

```
User Password
     │
     ▼
┌──────────────┐
│  PBKDF2-SHA256│  ← Key Derivation (crypto.php)
│  100,000 iters│
└──────┬───────┘
       │  Master Key (64 bytes raw)
       │
       ├──► Bytes  0–31  → AES-256-GCM Encryption Key (32 bytes)
       └──► Bytes 32–63  → PRNG Seed (32 bytes)

Secret File(s)
     │
     ▼
┌────────────┐
│ ZIP Bundle │  ← ZipArchive (process_encode.php)
└─────┬──────┘
      │ Raw ZIP bytes
      ▼
┌──────────────────┐
│ zlib Compress    │  ← gzcompress(level 9) (process_encode.php)
│ (DEFLATE level 9)│
└──────┬───────────┘
       │ Compressed bytes
       ▼
┌───────────────┐
│ AES-256-GCM   │  ← Encrypt (crypto.php)
│ Encrypt       │
└──────┬────────┘
       │ Ciphertext + 16-byte Auth Tag
       ▼
┌───────────────────┐
│  Payload Header   │  ← 33-byte structured header (payload.php)
│  + Ciphertext     │     [salt(16) | iv(12) | lsb_mode(1) | body_len(4)]
│  + Auth Tag       │
└──────┬────────────┘
       │ Binary payload
       ▼
┌──────────────────────┐
│  LSB Steganography   │  ← embed_lsb() (lsb.php)
│  Cover Image (PNG/JPEG)│
└──────────────────────┘
       │
       ▼
  Stego PNG (downloadable)
```

---

## Cryptographic Pipeline

### Step 1 — Salt & IV Generation
```
salt = random_bytes(16)   // 16-byte cryptographic salt
iv   = random_bytes(12)   // 12-byte AES-GCM nonce
```
Both are generated fresh for every encode operation using PHP's `random_bytes()` (CSPRNG). They are stored unencrypted inside the 33-byte header so they can be recovered during decode.

---

### Step 2 — Key Derivation: PBKDF2-SHA256
```
masterKey = PBKDF2(
    algo       = SHA-256,
    password   = user_password,
    salt       = salt,
    iterations = 100,000,
    keyLength  = 64 bytes,
    raw        = true
)

encKey   = masterKey[0..31]   // 32 bytes → AES-256 key
prngSeed = masterKey[32..63]  // 32 bytes → PRNG shuffle seed
```

- **100,000 iterations** (NIST recommended minimum for PBKDF2-SHA256) make brute-force attacks computationally expensive.
- The same password + salt always derives the same keys — this is deterministic and required for decoding.

---

### Step 3 — Compression: zlib DEFLATE
```
compressed = gzcompress(zip_bytes, level=9)   // PHP zlib (DEFLATE)
```

- Applied **after** ZIP creation and **before** AES encryption.
- Uses **level 9** (maximum compression) to minimise the number of pixels modified in the cover image.
- Reduces payload size, increasing the range of images that can carry the data.
- On decode, `gzuncompress()` is called **after** AES-GCM decryption to recover the original ZIP bytes.
- Both functions throw a `RuntimeException` on failure to prevent silent data corruption.

---

### Step 4 — Encryption: AES-256-GCM
```
(ciphertext, authTag) = AES_256_GCM_Encrypt(
    plaintext = compressed_bytes,
    key       = encKey,       // 32 bytes
    iv        = iv,           // 12 bytes
    tagLen    = 16 bytes
)
```

- **AES-256-GCM** provides both confidentiality (encryption) and integrity (authentication tag).
- The **16-byte authentication tag** prevents any tampering with the ciphertext from going undetected.
- An incorrect password during decode causes `openssl_decrypt()` to return `false`, safely rejecting the attempt.
- Because compression runs before encryption, the ciphertext is already smaller — no padding waste.

---

### Step 5 — Payload Construction
The complete binary payload embedded into the image is structured as:

```
┌──────────┬──────────┬──────────┬────────────┬──────────────┬─────────┐
│  salt    │  iv      │ lsb_mode │  body_len  │  ciphertext  │ authTag │
│ 16 bytes │ 12 bytes │  1 byte  │  4 bytes   │  variable    │ 16 bytes│
└──────────┴──────────┴──────────┴────────────┴──────────────┴─────────┘
└──────────────── 33-byte Header ────────────┘└────── Body (encrypted) ─┘
```

The **33-byte header** is always written to the first sequential pixels of the image using LSB-1. The encrypted body is distributed across the remaining pixels using the PRNG shuffle.

---

## Steganographic Engine

### LSB Embedding (`lsb.php`)

The engine uses PHP's built-in **GD extension** and operates on raw pixel RGB values.

#### Header Embedding (Sequential)
The 33-byte header is written to the very first pixels of the cover image, starting at pixel 0, using **1 LSB per channel**:

```
pixel[i].R = (pixel[i].R & 0xFE) | header_bit
pixel[i].G = (pixel[i].G & 0xFE) | header_bit
pixel[i].B = (pixel[i].B & 0xFE) | header_bit
```

3 bits per pixel × 102 pixels ≈ 306 bits = 33 bytes. Minimal image area is used.

#### Body Embedding (PRNG-Shuffled)
The encrypted payload body is scattered across the remaining pixels using **Fisher-Yates shuffle** seeded by the PRNG:

```
// Fisher-Yates partial shuffle (only shuffles as many as needed)
for i from headerPixels to pixelsNeeded:
    j = i + prng_int(seed, counter++, remaining)
    swap(pixelIndex[i], pixelIndex[j])
```

In **LSB-1 mode** (Sharing): 1 bit per channel (3 bits/pixel), lower visual distortion  
In **LSB-2 mode** (Storage): 2 bits per channel (6 bits/pixel), double capacity

#### PRNG Design (`prng.php`)
```
hash = SHA-256(seed || pack('N', counter))
clamped_val = bitwise mask of hash[0..3] into 31-bit positive int
random_int = clamped_val % (max + 1)
```

A deterministic counter-based PRNG using SHA-256. The same `seed` + `counter` always produces the same sequence. The 31-bit clamping ensures perfect architecture symmetry (32-bit vs 64-bit PHP instances never overflow floats), guaranteeing encode/decode symmetry anywhere.

---

## Multi-File Support

When more than one secret file is selected, they are bundled into a **ZIP archive** before compression and encryption:

```
encode:
  ZipArchive::open(tmpfile)
  foreach secret_files as file:
      ZipArchive::addFile(file, original_filename)
  ZipArchive::close()
  zipBytes   = file_get_contents(tmpfile)   // raw ZIP
  compressed = gzcompress(zipBytes, 9)      // zlib DEFLATE
  → AES-256-GCM encrypt compressed bytes

decode:
  plaintext  = aes_decrypt(ciphertext)      // compressed bytes
  zipData    = gzuncompress(plaintext)      // original ZIP
  output as secret.zip (user extracts manually)
```

Single-file uploads are also wrapped in a ZIP to maintain a consistent pipeline format.

**Supported secret file types**: Any (txt, pdf, jpg, docx, zip, etc.)  
**Supported cover image types**: PNG, JPEG (output is always PNG to preserve LSBs losslessly)

---

## Security Design

| Threat | Mitigation |
|---|---|
| Brute-force login | `sleep(1)` on failed `password_verify()` + bcrypt hashing |
| CSRF attacks | Per-session CSRF tokens validated on all POST requests |
| SQL injection | PDO prepared statements throughout |
| Session fixation | `session_regenerate_id(true)` on login |
| XSS | `htmlspecialchars()` on all user-controlled output |
| Plaintext data in image | AES-256-GCM encryption before embedding |
| Tampered ciphertext | GCM auth tag (16 bytes) detects any modification |
| Multi-channel bit collisions | Sequenced loop state indexing prevents LSB-2 bit wiping across R/G/B |
| PHP Architecture Overflow | 31-bit bitwise masking in `prng.php` enforces complete cross-platform decoding immunity |
| Weak passwords | Client-side rules: length ≥ 8, uppercase, lowercase, number, special char |
| Session hijacking | `HttpOnly`, `SameSite=Strict`, `Secure` cookie flags |

---

## File Structure

```
steganography/
├── home.php            — Main UI (Encode/Decode forms)
├── history.php         — Operation log & audit trail for the user
├── settings.php        — Account management & secure password updates
├── nav.php             — Global dynamic navigation bar
├── login.php           — Authentication page
├── register.php        — User registration page
├── logout.php          — Session destroy + redirect
├── request_reset.php   — Password reset request handler
├── verify_reset.php    — Password reset token verification
├── db.php              — PDO database connection
├── crypto.php          — PBKDF2 key derivation + AES-256-GCM
├── lsb.php             — GD-based LSB embed/extract engine
├── prng.php            — Deterministic SHA-256 PRNG
├── payload.php         — Payload structure pack/unpack
├── process_encode.php  — Encode pipeline (ZIP → Compress → Encrypt → Embed)
├── process_decode.php  — Decode pipeline (Extract → Decrypt → Decompress → ZIP)
├── style.css           — Main stylesheet
├── nav.css             — Navigation and inner-page responsive UI styles
├── auth.css            — Authentication form components
├── style.js            — Shared JS (grid animation, password toggle)
├── logo.png            — Application logo (cohesive neon aesthetic)
├── COLLEGE_DOCUMENTATION.md— Comprehensive project documentation
├── .env                — Environment variables (SMTP configs)
├── composer.json       — Composer configuration
└── README.md           — This file
```

---

## Requirements

- **PHP** ≥ 8.0 with extensions: `gd`, `openssl`, `pdo_mysql`, `zip`, `zlib`, `fileinfo` (built-in by default)
- **MySQL/MariaDB** for user accounts
- **XAMPP** (or equivalent Apache stack) for local deployment
- **Composer** dependencies: `phpmailer/phpmailer`

### PHP Extensions Check
```php
php -m | grep -E "gd|openssl|pdo_mysql|zip|zlib|fileinfo"
```

### Recommended `php.ini` Settings
```ini
file_uploads = On
upload_max_filesize = 50M
post_max_size = 55M
memory_limit = 256M
max_execution_time = 120
```

---

> ⚠️ **Production Checklist**
> - Delete `info.php` (exposes server configuration)
> - Set `display_errors = Off` in `php.ini`
> - Use HTTPS for all traffic (enables `Secure` cookie flag)
> - Ensure `upload_tmp_dir` is not web-accessible
