<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see CacheCleanOutcome} values; implemented by the container build.
 */
#[CreatesInstancesOf(CacheCleanOutcome::class)]
interface CacheCleanOutcomeFactory
{
    public function create(bool $cleaned, string $reason): CacheCleanOutcome;
}
