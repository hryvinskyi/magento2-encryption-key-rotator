<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectProbeOutcomeFactory implements ProbeOutcomeFactory
{
    public function create(ProbeStatus $status, string $reason): ProbeOutcome
    {
        return new ProbeOutcome($status, $reason);
    }
}
