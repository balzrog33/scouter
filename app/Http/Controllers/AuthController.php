<?php

namespace App\Http\Controllers;

use App\Auth\Auth;
use App\Auth\JwtService;
use App\Auth\TokenRepository;
use App\Database\UserRepository;
use App\Http\Controller;
use App\Http\Request;
use App\Http\Response;

/**
 * Controller d'authentification par JWT Bearer (API externe, n8n, scripts…)
 *
 * Endpoints :
 *  - POST /auth/token    → échange email/password contre access + refresh token
 *  - POST /auth/refresh  → échange un refresh token contre une nouvelle paire (rotation)
 *  - POST /auth/revoke   → révoque un refresh token (logout côté API)
 *
 * Sécurité :
 *  - Rate-limit sur /auth/token (5 échecs par email / 15 min → 429)
 *  - Messages d'erreur génériques (pas d'énumération d'utilisateurs)
 *  - Refresh tokens hashés en base, rotation à chaque usage, révocation de toute
 *    la famille de tokens en cas de détection de réutilisation
 *
 * @package    Scouter
 * @subpackage Http\Controllers
 */
class AuthController extends Controller
{
    private const MAX_FAILURES = 5;
    private const FAILURE_WINDOW_SEC = 900; // 15 min

    private JwtService $jwt;
    private TokenRepository $tokens;
    private UserRepository $users;

    public function __construct(Auth $auth)
    {
        parent::__construct($auth);
        $this->jwt    = new JwtService();
        $this->tokens = new TokenRepository();
        $this->users  = new UserRepository();
    }

    /**
     * POST /auth/token
     * Body: { "email": "...", "password": "..." }
     * → { access_token, refresh_token, token_type, expires_in, refresh_expires_in }
     */
    public function token(Request $request): void
    {
        $email    = trim((string) $request->get('email', ''));
        $password = (string) $request->get('password', '');

        if ($email === '' || $password === '') {
            $this->error('Email et mot de passe requis', 400);
            return;
        }

        $identifier = strtolower($email);
        $ip = $this->clientIp();

        if ($this->tokens->countRecentFailures($identifier, self::FAILURE_WINDOW_SEC) >= self::MAX_FAILURES) {
            Response::json(
                ['success' => false, 'error' => 'Trop de tentatives, réessayez plus tard'],
                429
            );
            return;
        }

        $user = $this->users->getByEmail($email);
        if (!$user || !password_verify($password, $user->password_hash)) {
            $this->tokens->recordAuthAttempt($identifier, false, $ip);
            $this->error('Identifiants invalides', 401);
            return;
        }

        $this->tokens->recordAuthAttempt($identifier, true, $ip);

        $this->issueTokenPair(
            (int) $user->id,
            (string) $user->email,
            (string) ($user->role ?? 'user'),
            $this->userAgent(),
            $ip
        );
    }

    /**
     * POST /auth/refresh
     * Body: { "refresh_token": "..." }
     */
    public function refresh(Request $request): void
    {
        $refreshToken = (string) $request->get('refresh_token', '');
        if ($refreshToken === '') {
            $this->error('refresh_token requis', 400);
            return;
        }

        try {
            $decoded = $this->jwt->decode($refreshToken);
        } catch (\Throwable $e) {
            $this->error('Refresh token invalide', 401);
            return;
        }

        if (($decoded->type ?? null) !== 'refresh') {
            $this->error('Type de token invalide', 401);
            return;
        }

        $jti = (string) ($decoded->jti ?? '');
        $userId = (int) ($decoded->sub ?? 0);
        if ($jti === '' || $userId <= 0) {
            $this->error('Refresh token invalide', 401);
            return;
        }

        $stored = $this->tokens->findActiveByJti($jti);
        if (!$stored) {
            // JTI inconnu ou déjà consommé → suspicion de réutilisation.
            // Par précaution, on révoque toute la famille de tokens de l'utilisateur.
            $this->tokens->revokeAllForUser($userId);
            $this->error('Refresh token révoqué', 401);
            return;
        }

        if (!hash_equals($stored->token_hash, $this->jwt->hashToken($refreshToken))) {
            $this->error('Refresh token invalide', 401);
            return;
        }

        $user = $this->users->getById($userId);
        if (!$user) {
            $this->error('Utilisateur introuvable', 401);
            return;
        }

        // Rotation : on émet une nouvelle paire et on révoque l'ancien refresh.
        $access = $this->jwt->issueAccessToken(
            (int) $user->id,
            (string) $user->email,
            (string) ($user->role ?? 'user')
        );
        $newRefresh = $this->jwt->issueRefreshToken((int) $user->id);

        $this->tokens->storeRefresh(
            (int) $user->id,
            $newRefresh['jti'],
            $this->jwt->hashToken($newRefresh['token']),
            $newRefresh['expires_at'],
            $this->userAgent(),
            $this->clientIp()
        );
        $this->tokens->rotate($jti, $newRefresh['jti']);

        Response::json([
            'access_token'       => $access['token'],
            'token_type'         => 'Bearer',
            'expires_in'         => $access['expires_in'],
            'refresh_token'      => $newRefresh['token'],
            'refresh_expires_in' => $newRefresh['expires_in'],
        ]);
    }

    /**
     * POST /auth/revoke
     * Body: { "refresh_token": "..." }
     * Idempotent — répond toujours 200 pour éviter de fuiter l'existence du JTI.
     */
    public function revoke(Request $request): void
    {
        $refreshToken = (string) $request->get('refresh_token', '');
        if ($refreshToken !== '') {
            try {
                $decoded = $this->jwt->decode($refreshToken);
                if (($decoded->type ?? null) === 'refresh' && isset($decoded->jti)) {
                    $this->tokens->revoke((string) $decoded->jti);
                }
            } catch (\Throwable $e) {
                // idempotent — on ignore les erreurs de décodage
            }
        }
        $this->success([], 'Token révoqué');
    }

    private function issueTokenPair(
        int $userId,
        string $email,
        string $role,
        ?string $userAgent,
        ?string $ip
    ): void {
        $access = $this->jwt->issueAccessToken($userId, $email, $role);
        $refresh = $this->jwt->issueRefreshToken($userId);

        $this->tokens->storeRefresh(
            $userId,
            $refresh['jti'],
            $this->jwt->hashToken($refresh['token']),
            $refresh['expires_at'],
            $userAgent,
            $ip
        );

        Response::json([
            'access_token'       => $access['token'],
            'token_type'         => 'Bearer',
            'expires_in'         => $access['expires_in'],
            'refresh_token'      => $refresh['token'],
            'refresh_expires_in' => $refresh['expires_in'],
        ]);
    }

    private function clientIp(): ?string
    {
        return $_SERVER['REMOTE_ADDR'] ?? null;
    }

    private function userAgent(): ?string
    {
        $ua = $_SERVER['HTTP_USER_AGENT'] ?? null;
        return $ua !== null ? substr($ua, 0, 500) : null;
    }
}
