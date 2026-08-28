<?php

namespace Tihloh\Prefab\Auth\Services;

use PDO;
use RuntimeException;
use Tihloh\Prefab\DatabaseInterface;
use Tihloh\Prefab\PrefabConfig;
use Tihloh\Prefab\PrefabRuntime;
use Tihloh\Prefab\Auth\Adapters\PrefabUsersAuthProvider;
use Tihloh\Prefab\Auth\Contracts\AuthCredentialStoreInterface;
use Tihloh\Prefab\Auth\Contracts\AuthSessionStoreInterface;
use Tihloh\Prefab\Auth\Contracts\AuthUserProviderInterface;
use Tihloh\Prefab\Auth\Contracts\AuthenticatableUserInterface;
use Tihloh\Prefab\Auth\Credentials\PdoCredentialStore;
use Tihloh\Prefab\Auth\DTOs\AuthResult;
use Tihloh\Prefab\Auth\Session\NativeSessionStore;

/**
 * Standalone authentication service with optional Prefab auto-integration.
 *
 * Identity belongs to the host project/user provider. Password credentials may
 * live in Auth-owned storage, so the project's users table does not need a
 * password column. Legacy providers that expose authPasswordHash() remain
 * supported as a fallback.
 */
final class AuthManager
{
    private ?AuthUserProviderInterface $users = null;
    private ?AuthSessionStoreInterface $session = null;
    private ?AuthCredentialStoreInterface $credentials = null;
    private array $config = [];
    private ?object $context = null;
    private ?object $events = null;
    private ?object $autoLogger = null;

    public function __construct(
        AuthUserProviderInterface|array|null $users = null,
        ?AuthSessionStoreInterface $session = null,
    ) {
        if ($users instanceof AuthUserProviderInterface) {
            $this->users = $users;
            PrefabRuntime::recordResolution(
                'auth',
                'user_provider',
                'module-local',
                ['provider' => $users::class],
            );
        } elseif (is_array($users)) {
            $this->config = $users;
        }

        if ($session) {
            $this->session = $session;
            PrefabRuntime::recordResolution(
                'auth',
                'session',
                'module-local',
                ['provider' => $session::class],
            );
        }

        PrefabRuntime::register('auth', $this);
    }

    /** Resolve missing session/provider/credential/logger references. */
    public function prefabConfigure(): void
    {
        if (!$this->session) {
            $session = PrefabConfig::resolve('auth', 'session', $this->config);

            if ($session['value'] instanceof AuthSessionStoreInterface) {
                $this->session = $session['value'];
                PrefabRuntime::recordResolution(
                    'auth',
                    'session',
                    $session['source'],
                    ['provider' => $this->session::class],
                );
            } else {
                $sessionKey = PrefabConfig::resolve(
                    'auth',
                    'session_key',
                    $this->config,
                    'prefab_auth_user',
                );

                $this->session = new NativeSessionStore((string) $sessionKey['value']);
                PrefabRuntime::recordResolution(
                    'auth',
                    'session',
                    $sessionKey['source'],
                    [
                        'provider' => NativeSessionStore::class,
                        'session_key' => (string) $sessionKey['value'],
                    ],
                );
            }
        }

        if (!$this->users) {
            $provider = PrefabConfig::resolve('auth', 'provider', $this->config);

            if ($provider['value'] instanceof AuthUserProviderInterface) {
                $this->users = $provider['value'];
                PrefabRuntime::recordResolution(
                    'auth',
                    'user_provider',
                    $provider['source'],
                    ['provider' => $this->users::class],
                );
            } else {
                $entry = PrefabRuntime::resolveEntry('user_provider');
                $prefabUsers = PrefabRuntime::get('users');

                if ($entry && $prefabUsers && $entry['provider'] === 'prefab-users') {
                    $this->users = new PrefabUsersAuthProvider($prefabUsers);
                    PrefabRuntime::recordResolution(
                        'auth',
                        'user_provider',
                        'prefab-capability',
                        [
                            'provider' => $entry['provider'],
                            'adapter' => PrefabUsersAuthProvider::class,
                        ],
                    );
                } elseif ($entry && $entry['value'] instanceof AuthUserProviderInterface) {
                    $this->users = $entry['value'];
                    PrefabRuntime::recordResolution(
                        'auth',
                        'user_provider',
                        'prefab-capability',
                        ['provider' => $entry['provider']],
                    );
                }
            }
        }

        if (!$this->credentials) {
            $configured = PrefabConfig::resolve(
                'auth',
                'credential_store',
                $this->config,
            );

            if ($configured['value'] instanceof AuthCredentialStoreInterface) {
                $this->credentials = $configured['value'];
                PrefabRuntime::recordResolution(
                    'auth',
                    'credential_store',
                    $configured['source'],
                    ['provider' => $this->credentials::class],
                );
            } else {
                $database = $this->credentialDatabase();

                if ($database) {
                    $table = PrefabConfig::resolve(
                        'auth',
                        'credentials_table',
                        $this->config,
                        'prefab_auth_credentials',
                    );

                    $this->credentials = new PdoCredentialStore(
                        $database,
                        (string) $table['value'],
                    );

                    PrefabRuntime::recordResolution(
                        'auth',
                        'credential_store',
                        'database-store',
                        [
                            'provider' => PdoCredentialStore::class,
                            'table' => (string) $table['value'],
                        ],
                    );
                }
            }
        }

        if ($this->credentials) {
            PrefabRuntime::provide(
                'auth_credentials',
                $this->credentials,
                'prefab-auth',
            );
        }

        if (!$this->autoLogger) {
            $logger = PrefabRuntime::resolveEntry('logger');

            if ($logger) {
                $this->autoLogger = $logger['value'];
                PrefabRuntime::recordResolution(
                    'auth',
                    'logger',
                    'prefab-capability',
                    ['provider' => $logger['provider']],
                );
            }
        }

        PrefabRuntime::provide('actor_provider', $this, 'prefab-auth');
    }

    public function explain(): array
    {
        return PrefabRuntime::explain('auth');
    }

    public function useContext(object $context): self
    {
        $this->context = $context;
        return $this;
    }

    public function useEvents(object $events): self
    {
        $this->events = $events;
        return $this;
    }

    public function setPassword(int|string $userId, string $password): void
    {
        if ($password === '') {
            throw new RuntimeException('Password cannot be empty.');
        }

        if (!$this->provider()->findById($userId)) {
            throw new RuntimeException('Cannot set a password for an unknown user.');
        }

        $this->credentialStore()->setPasswordHash(
            $userId,
            password_hash($password, PASSWORD_DEFAULT),
        );
    }

    public function hasPassword(int|string $userId): bool
    {
        return $this->passwordHashForId($userId) !== null;
    }

    public function verifyPassword(int|string $userId, string $password): bool
    {
        $hash = $this->passwordHashForId($userId);

        return $hash !== null && password_verify($password, $hash);
    }

    public function changePassword(
        int|string $userId,
        string $currentPassword,
        string $newPassword,
    ): bool {
        if (!$this->verifyPassword($userId, $currentPassword)) {
            return false;
        }

        $this->setPassword($userId, $newPassword);
        return true;
    }

    public function removePassword(int|string $userId): void
    {
        $this->credentialStore()->remove($userId);
    }

    public function attempt(
        string $identifier,
        string $password,
        array $context = [],
    ): AuthResult {
        $user = $this->provider()->findByIdentifier($identifier);

        if (!$user || !$user->authIsActive()) {
            return $this->result(
                false,
                null,
                $this->log(
                    'auth.login_failed',
                    null,
                    $context,
                    ['identifier' => $identifier],
                ),
                'invalid_credentials',
            );
        }

        $hash = $this->passwordHashFor($user);

        if (!$hash || !password_verify($password, $hash)) {
            return $this->result(
                false,
                null,
                $this->log('auth.login_failed', $user->authId(), $context),
                'invalid_credentials',
            );
        }

        $this->session()->put($user->authId());

        return $this->result(
            true,
            $user,
            $this->log('auth.login', $user->authId(), $context),
        );
    }

    public function login(
        AuthenticatableUserInterface $user,
        array $context = [],
    ): AuthResult {
        if (!$user->authIsActive()) {
            return new AuthResult(false, null, null, 'inactive');
        }

        $this->session()->put($user->authId());

        return $this->result(
            true,
            $user,
            $this->log('auth.login', $user->authId(), $context),
        );
    }

    public function logout(array $context = []): AuthResult
    {
        $id = $this->session()->userId();
        $log = $this->log('auth.logout', $id, $context);
        $this->session()->forget();

        return $this->result(true, null, $log);
    }

    public function check(): bool
    {
        return $this->session()->userId() !== null;
    }

    public function id(): int|string|null
    {
        return $this->session()->userId();
    }

    public function user(): ?AuthenticatableUserInterface
    {
        $id = $this->session()->userId();

        return $id === null ? null : $this->provider()->findById($id);
    }

    private function provider(): AuthUserProviderInterface
    {
        if (!$this->users) {
            $this->prefabConfigure();
        }

        return $this->users
            ?? throw new RuntimeException(
                'Prefab Auth needs an auth provider or compatible user_provider capability.',
            );
    }

    private function session(): AuthSessionStoreInterface
    {
        if (!$this->session) {
            $this->prefabConfigure();
        }

        return $this->session
            ?? throw new RuntimeException('Prefab Auth session is unavailable.');
    }

    private function credentialStore(): AuthCredentialStoreInterface
    {
        if (!$this->credentials) {
            $this->prefabConfigure();
        }

        return $this->credentials
            ?? throw new RuntimeException(
                'Prefab Auth needs a credential store or database to manage passwords.',
            );
    }

    private function passwordHashFor(AuthenticatableUserInterface $user): ?string
    {
        if (!$this->credentials) {
            $this->prefabConfigure();
        }

        $stored = $this->credentials?->passwordHash($user->authId());

        return $stored ?: $user->authPasswordHash();
    }

    private function passwordHashForId(int|string $userId): ?string
    {
        $user = $this->provider()->findById($userId);

        return $user ? $this->passwordHashFor($user) : null;
    }

    private function credentialDatabase(): DatabaseInterface|PDO|null
    {
        $direct = $this->config['database'] ?? null;
        if ($direct instanceof DatabaseInterface || $direct instanceof PDO) {
            return $direct;
        }

        $module = PrefabConfig::moduleOnly('auth');
        $moduleDatabase = $module['database'] ?? null;
        if ($moduleDatabase instanceof DatabaseInterface || $moduleDatabase instanceof PDO) {
            return $moduleDatabase;
        }

        $common = PrefabConfig::get('database');
        if ($common instanceof DatabaseInterface || $common instanceof PDO) {
            return $common;
        }

        $entry = PrefabRuntime::resolveEntry('database');
        $value = $entry['value'] ?? null;

        return $value instanceof DatabaseInterface || $value instanceof PDO
            ? $value
            : null;
    }

    private function result(
        bool $success,
        ?AuthenticatableUserInterface $user,
        ?array $log,
        ?string $error = null,
    ): AuthResult {
        if ($log) {
            if ($this->events && method_exists($this->events, 'dispatch')) {
                $this->events->dispatch('prefab.log', $log);
            } elseif ($this->autoLogger && method_exists($this->autoLogger, 'record')) {
                $this->autoLogger->record($log);
            }
        }

        return new AuthResult($success, $user, $log, $error);
    }

    private function log(
        string $action,
        int|string|null $userId,
        array $context,
        array $metadata = [],
    ): array {
        $base = ($this->context && method_exists($this->context, 'logContext'))
            ? $this->context->logContext()
            : [];

        $context = array_replace($base, $context);
        $actorId = $action === 'auth.login_failed'
            ? ($context['actor_id'] ?? null)
            : $userId;

        return [
            'action' => $action,
            'subject_type' => 'user',
            'subject_id' => $userId,
            'actor_type' => $actorId !== null ? 'user' : null,
            'actor_id' => $actorId,
            'message' => match ($action) {
                'auth.login' => 'User signed in.',
                'auth.logout' => 'User signed out.',
                default => 'Sign-in attempt failed.',
            },
            'metadata' => array_merge($metadata, $context['metadata'] ?? []),
            'ip_address' => $context['ip_address'] ?? null,
            'user_agent' => $context['user_agent'] ?? null,
        ];
    }
}
