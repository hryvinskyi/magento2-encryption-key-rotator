<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettingsFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectDatabaseSettingsFactory implements DatabaseSettingsFactory
{
    public function create(
        string $host,
        ?int $port,
        ?string $socket,
        string $dbname,
        string $user,
        #[\SensitiveParameter]
        string $password,
        string $tablePrefix,
        string $initStatements,
    ): DatabaseSettings {
        return new DatabaseSettings($host, $port, $socket, $dbname, $user, $password, $tablePrefix, $initStatements);
    }
}
