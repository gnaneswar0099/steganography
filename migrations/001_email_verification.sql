-- ============================================================
-- Migration 001: Email Verification
-- Database: Steganography (case-sensitive on Aiven MySQL 8.4)
-- ============================================================

USE Steganography;

-- 1. Add email_verified column to users table
ALTER TABLE users ADD COLUMN email_verified TINYINT(1) NOT NULL DEFAULT 0;

-- 2. Tokens table for email activation links
CREATE TABLE IF NOT EXISTS email_verifications (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    email      VARCHAR(255) NOT NULL,
    token_hash CHAR(64)     NOT NULL,
    expires_at DATETIME     NOT NULL,
    created_at TIMESTAMP    DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_email_verifications_token_hash (token_hash),
    INDEX idx_email_verifications_email (email),
    INDEX idx_email_verifications_expires_at (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- 3. Rate limiting table for verification and resend requests
CREATE TABLE IF NOT EXISTS email_verification_attempts (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    email        VARCHAR(255) NOT NULL,
    ip_address   VARCHAR(45)  NOT NULL,
    attempt_time DATETIME     NOT NULL,
    INDEX idx_email_verification_attempts_email (email),
    INDEX idx_email_verification_attempts_ip    (ip_address),
    INDEX idx_email_verification_attempts_time  (attempt_time)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;