<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Psr\Clock\ClockInterface;

/**
 * A clock that moves on by a fixed step every time it is read, so a test can make anything an adapter
 * times look as slow as it needs.
 */
final class AdvancingClock implements ClockInterface
{
    public function __construct(
        private \DateTimeImmutable $now,
        private readonly \DateInterval $step,
    ) {}

    public function now(): \DateTimeImmutable
    {
        $now = $this->now;
        $this->now = $now->add($this->step);

        return $now;
    }
}
