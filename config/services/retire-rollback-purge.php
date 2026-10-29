<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * Retiring the old keys, rolling a rotation back and purging a finished run. The values these use cases
 * exchange are created by generated factories, so the load of src/ must not register them as services.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services();

    foreach ([
        RetireRequest::class,
        RetireResult::class,
        RollBackRequest::class,
        RollBackResult::class,
        JournalReversalOutcome::class,
        PurgeRequest::class,
        PurgeResult::class,
    ] as $value) {
        $services->remove($value);
    }
};
