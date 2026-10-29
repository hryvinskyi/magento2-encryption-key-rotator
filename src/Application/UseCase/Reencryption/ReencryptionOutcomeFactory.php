<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ReencryptionOutcome} values; implemented by the container build.
 */
#[CreatesInstancesOf(ReencryptionOutcome::class)]
interface ReencryptionOutcomeFactory
{
    /**
     * @param array<string, int>                $applied
     * @param list<Conflict>                    $conflicts
     * @param array<string, array<string, int>> $skipped
     */
    public function create(array $applied, array $conflicts, array $skipped, int $passes): ReencryptionOutcome;
}
