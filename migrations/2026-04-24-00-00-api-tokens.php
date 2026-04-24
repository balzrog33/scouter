<?php
/**
 * Migration: API token authentication (JWT Bearer)
 *
 * Creates:
 *  - api_refresh_tokens : stores hashed refresh tokens for revocation/rotation
 *  - api_auth_attempts  : records login attempts for rate-limiting
 */

use App\Database\PostgresDatabase;

$pdo = PostgresDatabase::getInstance()->getConnection();

try {
    // =============================================
    // api_refresh_tokens
    // =============================================
    $stmt = $pdo->query("
        SELECT table_name FROM information_schema.tables
        WHERE table_name = 'api_refresh_tokens'
    ");

    if ($stmt->fetch()) {
        echo "   → Table api_refresh_tokens already exists, skipping\n";
    } else {
        echo "   → Creating api_refresh_tokens table... ";
        $pdo->exec("
            CREATE TABLE api_refresh_tokens (
                id SERIAL PRIMARY KEY,
                user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                jti VARCHAR(64) NOT NULL UNIQUE,
                token_hash VARCHAR(128) NOT NULL,
                expires_at TIMESTAMP NOT NULL,
                revoked_at TIMESTAMP DEFAULT NULL,
                replaced_by_jti VARCHAR(64) DEFAULT NULL,
                user_agent TEXT DEFAULT NULL,
                ip_address VARCHAR(45) DEFAULT NULL,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                last_used_at TIMESTAMP DEFAULT NULL
            )
        ");
        $pdo->exec("CREATE INDEX idx_api_refresh_tokens_user ON api_refresh_tokens(user_id)");
        $pdo->exec("CREATE INDEX idx_api_refresh_tokens_active ON api_refresh_tokens(jti) WHERE revoked_at IS NULL");
        echo "OK\n";
    }

    // =============================================
    // api_auth_attempts (rate-limit)
    // =============================================
    $stmt = $pdo->query("
        SELECT table_name FROM information_schema.tables
        WHERE table_name = 'api_auth_attempts'
    ");

    if ($stmt->fetch()) {
        echo "   → Table api_auth_attempts already exists, skipping\n";
    } else {
        echo "   → Creating api_auth_attempts table... ";
        $pdo->exec("
            CREATE TABLE api_auth_attempts (
                id SERIAL PRIMARY KEY,
                identifier VARCHAR(255) NOT NULL,
                success BOOLEAN NOT NULL DEFAULT FALSE,
                ip_address VARCHAR(45) DEFAULT NULL,
                attempted_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        ");
        $pdo->exec("CREATE INDEX idx_api_auth_attempts_identifier ON api_auth_attempts(identifier, attempted_at)");
        echo "OK\n";
    }

    echo "   ✓ Migration completed successfully\n";
    return true;

} catch (Exception $e) {
    echo "\n   ✗ Error: " . $e->getMessage() . "\n";
    return false;
}
