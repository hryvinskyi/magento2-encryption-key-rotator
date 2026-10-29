<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\MutableProbeContext;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

use function Symfony\Component\DependencyInjection\Loader\Configurator\inline_service;

/*
 * The tool's real service configuration, with the command context a command would set (the Magento
 * root, the probe settings, the state directory) and the operator output played by test doubles, and
 * one more worker activity source that joins the collection by implementing the port. The ports the
 * runtime adapters serve get a public alias `test.<interface>`.
 */
return static function (ContainerConfigurator $container): void {
    $container->import(dirname(__DIR__, 3) . '/config/services.php');

    $services = $container->services()->defaults()->autowire()->autoconfigure();
    $services->set(MutableProbeContext::class);
    $services->alias(MagentoRootProvider::class, MutableProbeContext::class);
    $services->alias(ProbeSettingsProvider::class, MutableProbeContext::class);
    $services->alias(StateDirectoryProvider::class, MutableProbeContext::class);
    $services->set(RecordingProgress::class);
    $services->alias(Progress::class, RecordingProgress::class);
    $services->set('test.fixture_worker_source', FixedWorkerActivity::class)
        ->args([[inline_service(RunningProcess::class)->args(['a worker of the fixture source', null])]]);

    foreach ([
        MutableProbeContext::class,
        RecordingProgress::class,
        WebTierProbe::class,
        WorkerActivity::class,
        ConfigCacheCleaner::class,
        SecretRedactor::class,
        RuntimeUser::class,
        Pause::class,
    ] as $id) {
        $services->alias('test.' . $id, $id)->public();
    }
};
