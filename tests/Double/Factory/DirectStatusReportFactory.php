<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\StatusReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\StatusReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectStatusReportFactory implements StatusReportFactory
{
    public function create(?RotationRun $run, array $nextCommands, ?string $deploymentRingFingerprint): StatusReport
    {
        return new StatusReport($run, $nextCommands, $deploymentRingFingerprint);
    }
}
