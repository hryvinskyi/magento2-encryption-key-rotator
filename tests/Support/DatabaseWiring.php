<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;

/**
 * Hands the container built for a wiring test the deployment configuration of that test's database.
 */
final class DatabaseWiring
{
    private static ?InMemoryDeploymentConfig $deploymentConfig = null;

    public static function use(InMemoryDeploymentConfig $deploymentConfig): void
    {
        self::$deploymentConfig = $deploymentConfig;
    }

    public static function deploymentConfig(): InMemoryDeploymentConfig
    {
        return self::$deploymentConfig ?? throw new \LogicException('No database was handed to the wiring test.');
    }
}
