<?php

namespace Tihloh\Prefab\Auth\Adapters;

use Tihloh\Prefab\Auth\Contracts\AuthUserProviderInterface;
use Tihloh\Prefab\Auth\Contracts\AuthenticatableUserInterface;

final class PrefabUsersAuthProvider implements AuthUserProviderInterface
{
    public function __construct(private object $users) {}

    public function findByIdentifier(string $identifier): ?AuthenticatableUserInterface
    {
        if (!method_exists($this->users, 'findByEmail')) return null;

        return $this->adapt($this->users->findByEmail($identifier));
    }

    public function findById(int|string $id): ?AuthenticatableUserInterface
    {
        if (!method_exists($this->users, 'find')) return null;

        return $this->adapt($this->users->find($id));
    }

    private function adapt(mixed $user): ?AuthenticatableUserInterface
    {
        if ($user instanceof AuthenticatableUserInterface) {
            return $user;
        }

        if (!is_object($user) || !isset($user->id)) {
            return null;
        }

        return new PrefabUserAuthIdentity($user);
    }
}
