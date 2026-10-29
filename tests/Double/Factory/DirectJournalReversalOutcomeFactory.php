<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcomeFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectJournalReversalOutcomeFactory implements JournalReversalOutcomeFactory
{
    public function create(int $reverted, int $superseded, array $leftAlone): JournalReversalOutcome
    {
        return new JournalReversalOutcome($reverted, $superseded, $leftAlone);
    }
}
