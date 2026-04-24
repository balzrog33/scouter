<?php

namespace App\Auth;

use Firebase\JWT\JWT;
use Firebase\JWT\Key;

/**
 * Encodage/décodage des JSON Web Tokens (JWT)
 *
 * Implémente l'authentification stateless via tokens signés HS256 avec :
 *  - Algorithme figé (protection contre l'attaque alg=none)
 *  - Claims standards (iss, aud, iat, nbf, exp, jti, sub)
 *  - Vérification stricte de l'émetteur et de l'audience
 *  - Paires access-token court / refresh-token long
 *
 * Config via variables d'environnement :
 *  - JWT_SECRET       (≥ 32 caractères, OBLIGATOIRE)
 *  - JWT_ISSUER       (défaut: "scouter")
 *  - JWT_ACCESS_TTL   (secondes, défaut 900 = 15 min)
 *  - JWT_REFRESH_TTL  (secondes, défaut 2592000 = 30 jours)
 *
 * @package    Scouter
 * @subpackage Auth
 */
class JwtService
{
    private const ALGORITHM = 'HS256';
    private const MIN_SECRET_LENGTH = 32;

    private string $secret;
    private string $issuer;
    private int $accessTtl;
    private int $refreshTtl;

    public function __construct()
    {
        $secret = (string) (getenv('JWT_SECRET') ?: ($_ENV['JWT_SECRET'] ?? ''));
        if (strlen($secret) < self::MIN_SECRET_LENGTH) {
            throw new \RuntimeException(
                'JWT_SECRET must be defined and at least ' . self::MIN_SECRET_LENGTH . ' characters long'
            );
        }
        $this->secret = $secret;
        $this->issuer = (string) (getenv('JWT_ISSUER') ?: ($_ENV['JWT_ISSUER'] ?? 'scouter'));
        $this->accessTtl = (int) (getenv('JWT_ACCESS_TTL') ?: ($_ENV['JWT_ACCESS_TTL'] ?? 900));
        $this->refreshTtl = (int) (getenv('JWT_REFRESH_TTL') ?: ($_ENV['JWT_REFRESH_TTL'] ?? 2592000));

        if ($this->accessTtl < 60 || $this->refreshTtl < $this->accessTtl) {
            throw new \RuntimeException('Invalid JWT TTL configuration');
        }
    }

    /**
     * Émet un access token de courte durée.
     *
     * @return array{token:string,expires_in:int,jti:string,expires_at:int}
     */
    public function issueAccessToken(int $userId, string $email, string $role): array
    {
        return $this->issueToken('access', $userId, $this->accessTtl, [
            'email' => $email,
            'role'  => $role,
        ]);
    }

    /**
     * Émet un refresh token de longue durée.
     *
     * @return array{token:string,expires_in:int,jti:string,expires_at:int}
     */
    public function issueRefreshToken(int $userId): array
    {
        return $this->issueToken('refresh', $userId, $this->refreshTtl);
    }

    /**
     * Décode un JWT en validant signature, issuer, audience, exp et nbf.
     *
     * @throws \Throwable si le token est invalide / expiré
     */
    public function decode(string $token): object
    {
        $decoded = JWT::decode($token, new Key($this->secret, self::ALGORITHM));

        if (!isset($decoded->iss) || !hash_equals($this->issuer, (string) $decoded->iss)) {
            throw new \UnexpectedValueException('Invalid issuer');
        }
        if (!isset($decoded->aud) || !hash_equals($this->issuer, (string) $decoded->aud)) {
            throw new \UnexpectedValueException('Invalid audience');
        }
        if (!isset($decoded->type) || !in_array($decoded->type, ['access', 'refresh'], true)) {
            throw new \UnexpectedValueException('Invalid token type');
        }

        return $decoded;
    }

    /**
     * Hash SHA-256 pour stockage en base (on ne stocke jamais le token en clair).
     */
    public function hashToken(string $token): string
    {
        return hash('sha256', $token);
    }

    public function getAccessTtl(): int
    {
        return $this->accessTtl;
    }

    public function getRefreshTtl(): int
    {
        return $this->refreshTtl;
    }

    /**
     * @return array{token:string,expires_in:int,jti:string,expires_at:int}
     */
    private function issueToken(string $type, int $userId, int $ttl, array $extra = []): array
    {
        $now = time();
        $jti = bin2hex(random_bytes(16));
        $exp = $now + $ttl;

        $payload = array_merge([
            'iss'  => $this->issuer,
            'aud'  => $this->issuer,
            'iat'  => $now,
            'nbf'  => $now,
            'exp'  => $exp,
            'jti'  => $jti,
            'sub'  => (string) $userId,
            'type' => $type,
        ], $extra);

        $token = JWT::encode($payload, $this->secret, self::ALGORITHM);

        return [
            'token'      => $token,
            'expires_in' => $ttl,
            'jti'        => $jti,
            'expires_at' => $exp,
        ];
    }
}
