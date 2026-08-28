<?php

namespace Tihloh\Prefab\Auth\Adapters;

use Tihloh\Prefab\Auth\Contracts\AuthenticatableUserInterface;

final class PrefabUserAuthIdentity implements AuthenticatableUserInterface
{
    public function __construct(private object $user) {}

    public function authId(): int|string
    {
        return $this->user->id;
    }

    public function authPasswordHash(): ?string
    {
        return null;
    }

    public function authIsActive(): bool
    {
        return property_exists($this->user, 'active')
            ? (bool) $this->user->active
            : true;
    }

    public function __get(string $name): mixed
    {
        return $this->user->{$name} ?? null;
    }

    public function __isset(string $name): bool
    {
        return isset($this->user->{$name});
    }

    public function source(): object
    {
        return $this->user;
    }
}
