<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;

/**
 * Pauses the tool's process for real, with the system's sleep.
 */
final class SleepingPause implements Pause
{
    public function pause(int $seconds): void
    {
        if ($seconds > 0) {
            sleep($seconds);
        }
    }
}
