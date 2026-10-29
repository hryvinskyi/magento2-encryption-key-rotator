<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Opens database connections; implemented by the container build.
 */
#[CreatesInstancesOf(\PDO::class)]
interface PdoFactory
{
    /**
     * @param string               $dsn      the data source name, without the user or the password
     * @param array<int, int|bool> $options  connection attributes
     *
     * @throws \PDOException when the server cannot be reached or refuses the login
     */
    public function create(
        string $dsn,
        ?string $username,
        #[\SensitiveParameter]
        ?string $password,
        array $options,
    ): \PDO;
}
