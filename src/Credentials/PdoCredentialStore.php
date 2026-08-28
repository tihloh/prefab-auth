<?php

namespace Tihloh\Prefab\Auth\Credentials;

use PDO;
use RuntimeException;
use Tihloh\Prefab\DatabaseInterface;
use Tihloh\Prefab\PdoDatabaseAdapter;
use Tihloh\Prefab\Auth\Contracts\AuthCredentialStoreInterface;

final class PdoCredentialStore implements AuthCredentialStoreInterface
{
    private DatabaseInterface $database;

    public function __construct(
        DatabaseInterface|PDO $database,
        private string $table = 'prefab_auth_credentials',
    ) {
        $this->database = $database instanceof PDO
            ? new PdoDatabaseAdapter($database)
            : $database;

        $this->assertIdentifier($this->table);
        $this->ensureSchema();
    }

    public function passwordHash(int|string $userId): ?string
    {
        $sql = $this->database->driver() === 'sqlsrv'
            ? "SELECT TOP 1 password_hash FROM {$this->table} WHERE user_id = :id"
            : "SELECT password_hash FROM {$this->table} WHERE user_id = :id LIMIT 1";

        $rows = $this->database->select($sql, ['id' => (string) $userId]);
        $hash = $rows[0]['password_hash'] ?? null;

        return is_string($hash) && $hash !== '' ? $hash : null;
    }

    public function setPasswordHash(int|string $userId, string $hash): void
    {
        $params = [
            'id' => (string) $userId,
            'hash' => $hash,
        ];

        $sql = match ($this->database->driver()) {
            'sqlite' => "INSERT INTO {$this->table} (user_id, password_hash, created_at, updated_at)
                VALUES (:id, :hash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    password_hash = excluded.password_hash,
                    updated_at = CURRENT_TIMESTAMP",

            'pgsql' => "INSERT INTO {$this->table} (user_id, password_hash, created_at, updated_at)
                VALUES (:id, :hash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON CONFLICT(user_id) DO UPDATE SET
                    password_hash = EXCLUDED.password_hash,
                    updated_at = CURRENT_TIMESTAMP",

            'sqlsrv' => "MERGE {$this->table} AS target
                USING (SELECT :id AS user_id, :hash AS password_hash) AS source
                ON target.user_id = source.user_id
                WHEN MATCHED THEN
                    UPDATE SET password_hash = source.password_hash, updated_at = CURRENT_TIMESTAMP
                WHEN NOT MATCHED THEN
                    INSERT (user_id, password_hash, created_at, updated_at)
                    VALUES (source.user_id, source.password_hash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP);",

            'mysql' => "INSERT INTO {$this->table} (user_id, password_hash, created_at, updated_at)
                VALUES (:id, :hash, CURRENT_TIMESTAMP, CURRENT_TIMESTAMP)
                ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), updated_at = CURRENT_TIMESTAMP",

            default => throw new RuntimeException(
                "Unsupported auth credential database driver '{$this->database->driver()}'.",
            ),
        };

        $this->database->statement($sql, $params);
    }

    public function remove(int|string $userId): void
    {
        $this->database->statement(
            "DELETE FROM {$this->table} WHERE user_id = :id",
            ['id' => (string) $userId],
        );
    }

    private function ensureSchema(): void
    {
        $sql = match ($this->database->driver()) {
            'sqlite' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                created_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",

            'pgsql' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id BIGSERIAL PRIMARY KEY,
                user_id VARCHAR(191) NOT NULL UNIQUE,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP
            )",

            'sqlsrv' => "IF OBJECT_ID(N'{$this->table}', N'U') IS NULL
                CREATE TABLE {$this->table} (
                    id BIGINT IDENTITY(1,1) PRIMARY KEY,
                    user_id NVARCHAR(191) NOT NULL UNIQUE,
                    password_hash NVARCHAR(255) NOT NULL,
                    created_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP,
                    updated_at DATETIME2 NOT NULL DEFAULT CURRENT_TIMESTAMP
                )",

            'mysql' => "CREATE TABLE IF NOT EXISTS {$this->table} (
                id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,
                user_id VARCHAR(191) NOT NULL,
                password_hash VARCHAR(255) NOT NULL,
                created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
                UNIQUE KEY uq_prefab_auth_credentials_user (user_id)
            ) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci",

            default => throw new RuntimeException(
                "Unsupported auth credential database driver '{$this->database->driver()}'.",
            ),
        };

        $this->database->statement($sql);
    }

    private function assertIdentifier(string $identifier): void
    {
        if (!preg_match('/^[A-Za-z_][A-Za-z0-9_]*$/', $identifier)) {
            throw new RuntimeException("Unsafe SQL identifier: {$identifier}");
        }
    }
}
