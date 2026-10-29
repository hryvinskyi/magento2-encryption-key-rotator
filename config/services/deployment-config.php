<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\EnvPhpDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\FilesystemRunStore;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\StateDirectoryLock;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The store's configuration files and the run store on disk. A lock holder belongs to one run store and
 * is created by its generated factory, so it is no service of its own.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $services->alias(DeploymentConfigReader::class, EnvPhpDeploymentConfig::class);
    $services->alias(DeploymentConfigWriter::class, EnvPhpDeploymentConfig::class);
    $services->alias(RunStore::class, FilesystemRunStore::class);

    $services->remove(StateDirectoryLock::class);
};
