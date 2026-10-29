<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Waits before a transaction the server aborted for a deadlock or a lock wait timeout is tried again.
 */
interface RetryPause
{
    /**
     * @param int $attempt the attempt that failed, from 1
     */
    public function after(int $attempt): void;
}
