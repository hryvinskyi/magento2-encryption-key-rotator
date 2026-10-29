<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;
use Symfony\Component\Clock\MockClock;

/**
 * A pause that moves a test's clock on instead of waiting, and remembers every pause it was asked for.
 */
final class ClockAdvancingPause implements Pause
{
    /**
     * @var list<int>
     */
    private array $pauses = [];

    public function __construct(
        private readonly MockClock $clock,
    ) {}

    public function pause(int $seconds): void
    {
        $this->pauses[] = $seconds;
        if ($seconds > 0) {
            $this->clock->sleep($seconds);
        }
    }

    /**
     * @return list<int> the seconds of every pause, oldest first
     */
    public function pauses(): array
    {
        return $this->pauses;
    }
}
