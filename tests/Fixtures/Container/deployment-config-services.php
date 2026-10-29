<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigMapper;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\NestedArray;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\PhpArrayFileLoader;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\FilesystemRunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SettableMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SettableStateDirectory;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, with the configuration-file and run-store adapters reachable
 * from a test as `test.<interface or class>`. The Magento root and the state directory, which the
 * command learns from its options, come from providers a test points at its scratch directories.
 * `test.fresh.run_store` gives a new run store on every call, with the real wiring: what a second
 * process opening the same state directory would hold.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    $services->set(SettableMagentoRoot::class)->public();
    $services->alias(MagentoRootProvider::class, SettableMagentoRoot::class);
    $services->set(SettableStateDirectory::class)->public();
    $services->alias(StateDirectoryProvider::class, SettableStateDirectory::class);

    $services->set('test.fresh.run_store', FilesystemRunStore::class)->autowire()->share(false)->public();

    foreach ([
        DeploymentConfigReader::class,
        DeploymentConfigWriter::class,
        RunStore::class,
        MagentoRootFactory::class,
        KeyRingParser::class,
        CiphertextParser::class,
        DeploymentConfigRenderer::class,
        PhpArrayFileLoader::class,
        DeploymentConfigMapper::class,
        NestedArray::class,
        AtomicFileWriter::class,
        FileOperations::class,
        MagentoRootProvider::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
