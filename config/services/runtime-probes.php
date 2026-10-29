<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\CompositeWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\MagentoCliConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\PsProcessTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\PosixRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\SleepingPause;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\TransportWebTierProbe;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpClient\HttpClient;
use Symfony\Contracts\HttpClient\HttpClientInterface;

use function Symfony\Component\DependencyInjection\Loader\Configurator\tagged_iterator;

/*
 * The adapters that look at the running store: the web tier probe and its transports, the worker
 * activity, the configuration cache cleaner, the secret redactor, the runtime user and the pause.
 *
 * Every probe transport and every worker activity source joins its collection by implementing the
 * interface: autoconfiguration tags it. The composite worker activity is the one implementation left
 * out of the tag, so it never receives itself.
 */
return static function (ContainerConfigurator $container, ContainerBuilder $builder): void {
    $builder->registerForAutoconfiguration(ProbeTransport::class)->addTag('key_rotator.probe_transport');
    $builder->registerForAutoconfiguration(WorkerActivity::class)->addTag('key_rotator.worker_activity');

    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $services->set(TransportWebTierProbe::class)
        ->arg('$transports', tagged_iterator('key_rotator.probe_transport'));
    $services->alias(WebTierProbe::class, TransportWebTierProbe::class);

    $services->set(HttpClientInterface::class)
        ->factory([HttpClient::class, 'create']);

    $services->set(CompositeWorkerActivity::class)
        ->autoconfigure(false)
        ->arg('$sources', tagged_iterator('key_rotator.worker_activity'));
    $services->alias(WorkerActivity::class, CompositeWorkerActivity::class);
    $services->alias(ProcessTable::class, PsProcessTable::class);

    $services->alias(ConfigCacheCleaner::class, MagentoCliConfigCacheCleaner::class);
    $services->alias(SecretRedactor::class, PatternSecretRedactor::class);
    $services->alias(RuntimeUser::class, PosixRuntimeUser::class);
    $services->alias(Pause::class, SleepingPause::class);
};
