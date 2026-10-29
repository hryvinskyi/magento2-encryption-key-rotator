<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ProbeOutcome} values; implemented by the container build.
 */
#[CreatesInstancesOf(ProbeOutcome::class)]
interface ProbeOutcomeFactory
{
    public function create(ProbeStatus $status, string $reason): ProbeOutcome;
}
