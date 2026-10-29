<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcomeFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectReencryptionOutcomeFactory implements ReencryptionOutcomeFactory
{
    public function create(array $applied, array $conflicts, array $skipped, int $passes): ReencryptionOutcome
    {
        return new ReencryptionOutcome($applied, $conflicts, $skipped, $passes);
    }
}
