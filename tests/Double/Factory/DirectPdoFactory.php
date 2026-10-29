<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectPdoFactory implements PdoFactory
{
    public function create(string $dsn, ?string $username, #[\SensitiveParameter] ?string $password, array $options): \PDO
    {
        return new \PDO($dsn, $username, $password, $options);
    }
}
