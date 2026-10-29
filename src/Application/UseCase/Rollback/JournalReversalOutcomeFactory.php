<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see JournalReversalOutcome} values; implemented by the container build.
 */
#[CreatesInstancesOf(JournalReversalOutcome::class)]
interface JournalReversalOutcomeFactory
{
    /**
     * @param list<Conflict> $leftAlone
     */
    public function create(int $reverted, int $superseded, array $leftAlone): JournalReversalOutcome;
}
