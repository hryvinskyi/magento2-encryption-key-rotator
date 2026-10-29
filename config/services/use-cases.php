<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFinding;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\StatusReport;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The use cases and the application services they share. The values they exchange are created by
 * generated factories, so the load of src/ must not register them as services.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    foreach ([
        ColumnFindings::class,
        SystemValueFinding::class,
        ScanReport::class,
        ReencryptionOutcome::class,
        Refusal::class,
        PreflightResult::class,
        RotateRequest::class,
        RotateResult::class,
        StatusReport::class,
    ] as $value) {
        $services->remove($value);
    }
};
