<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidateFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\RunSnapshotReader;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, with its run services and a sample of the factories of the
 * values the ports exchange reachable from a test: each gets a public alias `test.<interface or class>`,
 * so a test exercises exactly the objects and the generated factories the shipped container builds.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    foreach ([
        RotationRunFactory::class,
        ScanSummaryFactory::class,
        RunIdGenerator::class,
        RunSnapshotReader::class,
        RowKeyFactory::class,
        ColumnCandidateFactory::class,
        DatabaseSettingsFactory::class,
        ProbeSettingsFactory::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
