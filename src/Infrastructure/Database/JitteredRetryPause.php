<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Exponential backoff with full jitter: after attempt n a random wait up to 100 ms × 2^(n-1), so
 * transactions that collided do not collide again at the same moment.
 */
final class JitteredRetryPause implements RetryPause
{
    private const BASE_MICROSECONDS = 100_000;

    public function after(int $attempt): void
    {
        usleep(random_int(0, self::BASE_MICROSECONDS * 2 ** max(0, min($attempt - 1, 4))));
    }
}
