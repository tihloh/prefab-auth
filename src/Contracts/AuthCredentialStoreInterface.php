<?php

namespace Tihloh\Prefab\Auth\Contracts;

interface AuthCredentialStoreInterface
{
    public function passwordHash(int|string $userId): ?string;

    public function setPasswordHash(int|string $userId, string $hash): void;

    public function remove(int|string $userId): void;
}
