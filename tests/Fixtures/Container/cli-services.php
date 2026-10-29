<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, untouched, with a few services reachable from a test as
 * `test.<interface>`: the adapters that read the Magento root and the state directory, and the ports the
 * command context fills.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    foreach ([
        DeploymentConfigReader::class,
        RunStore::class,
        MagentoRootProvider::class,
        StateDirectoryProvider::class,
        Progress::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
