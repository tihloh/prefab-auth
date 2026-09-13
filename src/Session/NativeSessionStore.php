<?php

namespace Tihloh\Prefab\Auth\Session;

use Tihloh\Prefab\Auth\Contracts\AuthSessionStoreInterface;

final class NativeSessionStore implements AuthSessionStoreInterface
{
    private string $scopedKey;
    private string $startedKey;
    private string $activityKey;
    private ?string $expirationReason = null;

    public function __construct(
        private string $key = 'auth:user_id',
        private ?int $idleTimeout = null,
        private ?int $absoluteTimeout = null,
    ) {
        $this->idleTimeout = $this->normalizeTimeout($idleTimeout);
        $this->absoluteTimeout = $this->normalizeTimeout($absoluteTimeout);
        $gcLifetime = max($this->idleTimeout ?? 0, $this->absoluteTimeout ?? 0);
        if ($gcLifetime > 0 && session_status() !== PHP_SESSION_ACTIVE) {
            $current = (int) ini_get('session.gc_maxlifetime');
            if ($gcLifetime > $current) { @ini_set('session.gc_maxlifetime', (string) $gcLifetime); }
        }

        SessionScope::start();
        $this->scopedKey = SessionScope::key($this->key);
        $this->startedKey = SessionScope::key($this->key . ':started_at');
        $this->activityKey = SessionScope::key($this->key . ':last_activity_at');
    }

    public function put(int|string $userId): void
    {
        $now = time();
        $_SESSION[$this->scopedKey] = $userId;
        $_SESSION[$this->startedKey] = $now;
        $_SESSION[$this->activityKey] = $now;
        $this->expirationReason = null;
    }

    public function userId(): int|string|null
    {
        $userId = $_SESSION[$this->scopedKey] ?? null;
        if ($userId === null) { return null; }

        $now = time();
        $startedAt = (int) ($_SESSION[$this->startedKey] ?? $now);
        $lastActivityAt = (int) ($_SESSION[$this->activityKey] ?? $startedAt);

        if ($this->absoluteTimeout !== null && ($now - $startedAt) >= $this->absoluteTimeout) {
            $this->expire('absolute_timeout');
            return null;
        }
        if ($this->idleTimeout !== null && ($now - $lastActivityAt) >= $this->idleTimeout) {
            $this->expire('idle_timeout');
            return null;
        }

        $_SESSION[$this->startedKey] = $startedAt;
        $_SESSION[$this->activityKey] = $now;
        return $userId;
    }

    public function forget(): void
    {
        unset($_SESSION[$this->scopedKey], $_SESSION[$this->startedKey], $_SESSION[$this->activityKey]);
        $this->expirationReason = null;
    }

    public function consumeExpirationReason(): ?string
    {
        $reason = $this->expirationReason;
        $this->expirationReason = null;
        return $reason;
    }

    private function expire(string $reason): void
    {
        unset($_SESSION[$this->scopedKey], $_SESSION[$this->startedKey], $_SESSION[$this->activityKey]);
        $this->expirationReason = $reason;
    }

    private function normalizeTimeout(?int $seconds): ?int
    {
        return $seconds !== null && $seconds > 0 ? $seconds : null;
    }
}
