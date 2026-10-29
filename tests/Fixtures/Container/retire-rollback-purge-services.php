<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireOldKeys;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\MutableProbeContext;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The tool's real service configuration, with the retirement, rollback and purge use cases and the
 * factories of the values they exchange reachable from a test: each gets a public alias
 * `test.<interface or class>`, so a test resolves exactly what the shipped container builds. The
 * exceptions are what the console supplies once a command starts: the use cases' output port (a
 * recording double here) and the command's context (the Magento root, the state directory and the
 * probe settings, settable here).
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services();
    $services->set(MutableProbeContext::class);
    $services->alias(MagentoRootProvider::class, MutableProbeContext::class);
    $services->alias(ProbeSettingsProvider::class, MutableProbeContext::class);
    $services->alias(StateDirectoryProvider::class, MutableProbeContext::class);
    $services->set(RecordingProgress::class);
    $services->alias(Progress::class, RecordingProgress::class);
    foreach ([
        RetireOldKeys::class,
        RollBackRotation::class,
        PurgeRotation::class,
        RetireRequestFactory::class,
        RetireResultFactory::class,
        RollBackRequestFactory::class,
        RollBackResultFactory::class,
        JournalReversalOutcomeFactory::class,
        PurgeRequestFactory::class,
        PurgeResultFactory::class,
        ProbeSettingsFactory::class,
        RunIdFactory::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
