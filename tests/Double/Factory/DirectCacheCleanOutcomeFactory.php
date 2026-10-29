<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcomeFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectCacheCleanOutcomeFactory implements CacheCleanOutcomeFactory
{
    public function create(bool $cleaned, string $reason): CacheCleanOutcome
    {
        return new CacheCleanOutcome($cleaned, $reason);
    }
}
