-- Drop existing database for a clean install (demo project — destructive).
DROP DATABASE IF EXISTS `password_manager`;

CREATE DATABASE `password_manager` CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE `password_manager`;

-- Users
--   username_hmac     : HMAC-SHA256(server blind-index key, lowercased username) — hex
--   username_enc      : AES-256-GCM ciphertext of username (encrypted with the user's DEK)
--   kdf_salt          : Argon2id salt for the master-password KEK
--   kdf_params        : "argon2id,m=...,t=...,p=...,v=..." (allows future tuning + migration)
--   wrapped_dek       : DEK wrapped with the master-password-derived KEK (AES-GCM)
--   recovery_salt     : Argon2id salt for the recovery KEK
--   wrapped_dek_recovery : DEK wrapped with the recovery-code-derived KEK
--   totp_secret_enc   : TOTP secret encrypted with the DEK
--   last_totp_step    : last accepted TOTP time-step (replay defense)
--   failed_logins     : consecutive failed attempts
--   locked_until      : lockout expiration
CREATE TABLE `users` (
    `id`                    INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `username_hmac`         CHAR(64)        NOT NULL,
    `username_enc`          VARCHAR(512)    NOT NULL,
    `kdf_salt`              VARCHAR(255)    NOT NULL,
    `kdf_params`            VARCHAR(128)    NOT NULL,
    `wrapped_dek`           VARCHAR(255)    NOT NULL,
    `recovery_salt`         VARCHAR(255)    NOT NULL,
    `wrapped_dek_recovery`  VARCHAR(255)    NOT NULL,
    `totp_secret_enc`       VARCHAR(512)    NOT NULL,
    `last_totp_step`        BIGINT          NOT NULL DEFAULT 0,
    `failed_logins`         INT             NOT NULL DEFAULT 0,
    `locked_until`          DATETIME        NULL,
    `created_at`            DATETIME        DEFAULT CURRENT_TIMESTAMP,
    `last_login`            DATETIME        DEFAULT NULL,
    PRIMARY KEY (`id`),
    UNIQUE KEY `username_hmac_unique` (`username_hmac`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

-- Vault items
--   *_hmac : HMAC-SHA256(blind index key, lowercased plaintext) for indexable equality search
--   *_enc  : AES-256-GCM ciphertext under the user's DEK
CREATE TABLE `vault_items` (
    `id`                    INT UNSIGNED NOT NULL AUTO_INCREMENT,
    `user_id`               INT UNSIGNED NOT NULL,
    `service_name_hmac`     CHAR(64)        NOT NULL,
    `service_username_hmac` CHAR(64)        NOT NULL,
    `service_name_enc`      VARCHAR(512)    NOT NULL,
    `service_username_enc`  VARCHAR(512)    NOT NULL,
    `encrypted_password`    VARCHAR(1024)   NOT NULL,
    `notes_enc`             TEXT,
    `created_at`            DATETIME        DEFAULT CURRENT_TIMESTAMP,
    `updated_at`            DATETIME        DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
    PRIMARY KEY (`id`),
    FOREIGN KEY (`user_id`) REFERENCES `users`(`id`) ON DELETE CASCADE,
    INDEX `idx_user_service` (`user_id`, `service_name_hmac`),
    INDEX `idx_user_service_user` (`user_id`, `service_username_hmac`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
