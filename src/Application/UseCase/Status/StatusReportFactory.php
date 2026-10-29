<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see StatusReport} values; implemented by the container build.
 */
#[CreatesInstancesOf(StatusReport::class)]
interface StatusReportFactory
{
    /**
     * @param list<RunCommand> $nextCommands
     * @param string|null      $deploymentRingFingerprint the fingerprint of the ring `env.php` holds now, null when it holds no usable one
     */
    public function create(?RotationRun $run, array $nextCommands, ?string $deploymentRingFingerprint): StatusReport;
}
