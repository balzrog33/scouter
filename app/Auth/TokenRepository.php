<?php

namespace App\Auth;

use App\Database\PostgresDatabase;
use PDO;

/**
 * Repository des refresh tokens et des tentatives d'authentification
 *
 * Gère la persistance des refresh tokens (hashés) pour permettre la révocation
 * et la rotation, ainsi que le log des tentatives de login pour le rate-limiting.
 *
 * @package    Scouter
 * @subpackage Auth
 */
class TokenRepository
{
    private PDO $db;

    public function __construct(?PDO $db = null)
    {
        $this->db = $db ?? PostgresDatabase::getInstance()->getConnection();
    }

    /**
     * Enregistre un nouveau refresh token (hashé).
     */
    public function storeRefresh(
        int $userId,
        string $jti,
        string $tokenHash,
        int $expiresAt,
        ?string $userAgent,
        ?string $ip
    ): void {
        $stmt = $this->db->prepare("
            INSERT INTO api_refresh_tokens (user_id, jti, token_hash, expires_at, user_agent, ip_address)
            VALUES (:user_id, :jti, :token_hash, to_timestamp(:expires_at), :user_agent, :ip_address)
        ");
        $stmt->execute([
            ':user_id'    => $userId,
            ':jti'        => $jti,
            ':token_hash' => $tokenHash,
            ':expires_at' => $expiresAt,
            ':user_agent' => $userAgent,
            ':ip_address' => $ip,
        ]);
    }

    /**
     * Retourne un refresh token actif (non révoqué, non expiré) par son JTI.
     */
    public function findActiveByJti(string $jti): ?object
    {
        $stmt = $this->db->prepare("
            SELECT * FROM api_refresh_tokens
            WHERE jti = :jti AND revoked_at IS NULL AND expires_at > NOW()
        ");
        $stmt->execute([':jti' => $jti]);
        return $stmt->fetch(PDO::FETCH_OBJ) ?: null;
    }

    /**
     * Révoque un refresh token par son JTI et enregistre son remplaçant (rotation).
     */
    public function rotate(string $oldJti, string $newJti): void
    {
        $stmt = $this->db->prepare("
            UPDATE api_refresh_tokens
            SET revoked_at = NOW(), replaced_by_jti = :new_jti, last_used_at = NOW()
            WHERE jti = :old_jti AND revoked_at IS NULL
        ");
        $stmt->execute([':old_jti' => $oldJti, ':new_jti' => $newJti]);
    }

    /**
     * Révoque un refresh token (idempotent).
     */
    public function revoke(string $jti): void
    {
        $stmt = $this->db->prepare("
            UPDATE api_refresh_tokens SET revoked_at = NOW()
            WHERE jti = :jti AND revoked_at IS NULL
        ");
        $stmt->execute([':jti' => $jti]);
    }

    /**
     * Révoque tous les refresh tokens actifs d'un utilisateur.
     * Utile en cas de suspicion de compromission (ex: réutilisation d'un refresh token).
     */
    public function revokeAllForUser(int $userId): void
    {
        $stmt = $this->db->prepare("
            UPDATE api_refresh_tokens SET revoked_at = NOW()
            WHERE user_id = :user_id AND revoked_at IS NULL
        ");
        $stmt->execute([':user_id' => $userId]);
    }

    /**
     * Supprime les tokens expirés depuis plus de 7 jours (à appeler depuis un cron).
     */
    public function purgeExpired(): int
    {
        return (int) $this->db->exec(
            "DELETE FROM api_refresh_tokens WHERE expires_at < NOW() - INTERVAL '7 days'"
        );
    }

    // ==================== Rate-limit (tentatives de login) ====================

    public function recordAuthAttempt(string $identifier, bool $success, ?string $ip): void
    {
        $stmt = $this->db->prepare("
            INSERT INTO api_auth_attempts (identifier, success, ip_address)
            VALUES (:identifier, :success, :ip)
        ");
        $stmt->execute([
            ':identifier' => $identifier,
            ':success'    => $success ? 't' : 'f',
            ':ip'         => $ip,
        ]);
    }

    /**
     * Compte les échecs de login récents pour un identifiant (email) donné.
     */
    public function countRecentFailures(string $identifier, int $windowSeconds): int
    {
        $stmt = $this->db->prepare("
            SELECT COUNT(*) AS c FROM api_auth_attempts
            WHERE identifier = :identifier
              AND success = FALSE
              AND attempted_at > NOW() - make_interval(secs => :window)
        ");
        $stmt->execute([
            ':identifier' => $identifier,
            ':window'     => $windowSeconds,
        ]);
        $row = $stmt->fetch(PDO::FETCH_OBJ);
        return $row ? (int) $row->c : 0;
    }
}
