<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\CronScheduleActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseWiring;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, with the database adapters reachable from a test through a
 * public alias `test.<interface or class>`. The deployment configuration names the test's database, and
 * progress is recorded, since those are bound by other areas of the tool.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    $services->set(InMemoryDeploymentConfig::class)->factory([DatabaseWiring::class, 'deploymentConfig']);
    $services->alias(DeploymentConfigReader::class, InMemoryDeploymentConfig::class);
    $services->set(RecordingProgress::class);
    $services->alias(Progress::class, RecordingProgress::class);
    foreach ([
        EncryptedColumnFinder::class,
        CiphertextRows::class,
        ReencryptionWriter::class,
        JournalReverter::class,
        JournalPurger::class,
        JournalSchema::class,
        PdoFactory::class,
        CronScheduleActivity::class,
        RunRegistry::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
