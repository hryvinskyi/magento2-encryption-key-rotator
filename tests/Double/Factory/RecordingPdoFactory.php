<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoFactory;

/**
 * Records what a connection was asked for, then fails it the way the driver fails a connect, with a
 * message that carries the password: a test proves that message never travels further.
 */
final class RecordingPdoFactory implements PdoFactory
{
    /**
     * @var list<array{dsn: string, username: string|null, options: array<int, int|bool>}>
     */
    private array $calls = [];

    public function create(string $dsn, ?string $username, #[\SensitiveParameter] ?string $password, array $options): \PDO
    {
        $this->calls[] = ['dsn' => $dsn, 'username' => $username, 'options' => $options];

        throw new \PDOException(sprintf('SQLSTATE[HY000] [1045] Access denied for user \'%s\' (password %s)', $username ?? '', $password ?? ''));
    }

    /**
     * @return list<array{dsn: string, username: string|null, options: array<int, int|bool>}>
     */
    public function calls(): array
    {
        return $this->calls;
    }
}
