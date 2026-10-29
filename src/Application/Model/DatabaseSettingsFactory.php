<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see DatabaseSettings} values; implemented by the container build.
 */
#[CreatesInstancesOf(DatabaseSettings::class)]
interface DatabaseSettingsFactory
{
    /**
     * @throws InvalidValue when no database or user is named, or the port is out of range
     */
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
    ): DatabaseSettings;
}
