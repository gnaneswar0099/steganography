CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    email VARCHAR(255) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS login_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    attempt_time DATETIME NOT NULL,
    INDEX idx_login_attempts_email (email),
    INDEX idx_login_attempts_ip (ip_address),
    INDEX idx_login_attempts_time (attempt_time)
);

CREATE TABLE IF NOT EXISTS password_resets (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    token_hash CHAR(64) NOT NULL,
    expires_at DATETIME NOT NULL,
    request_ip VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    used TINYINT(1) NOT NULL DEFAULT 0,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    UNIQUE KEY uq_password_resets_token_hash (token_hash),
    INDEX idx_password_resets_email (email),
    INDEX idx_password_resets_expires_at (expires_at)
);

CREATE TABLE IF NOT EXISTS password_reset_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    email VARCHAR(255) NOT NULL,
    attempt_time DATETIME NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    INDEX idx_password_reset_attempts_email (email),
    INDEX idx_password_reset_attempts_time (attempt_time)
);

CREATE TABLE IF NOT EXISTS reset_verify_attempts (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    user_agent VARCHAR(255) NOT NULL,
    attempt_time DATETIME NOT NULL,
    INDEX idx_reset_verify_attempts_ip (ip_address),
    INDEX idx_reset_verify_attempts_time (attempt_time)
);

CREATE TABLE IF NOT EXISTS user_activity_log (
    id INT AUTO_INCREMENT PRIMARY KEY,
    user_id INT NOT NULL,
    operation ENUM('encode', 'decode') NOT NULL,
    cover_image_name VARCHAR(255) NOT NULL,
    secret_file_names TEXT NOT NULL,
    lsb_mode TINYINT(1) NULL,
    image_width INT NULL,
    image_height INT NULL,
    performed_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    INDEX idx_user_activity_user_id (user_id),
    INDEX idx_user_activity_performed_at (performed_at)
);
