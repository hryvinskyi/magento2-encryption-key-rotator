<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Lets time pass: a use case that waits for something outside the tool (the web tier reloading its
 * configuration) waits through this port, so the wait itself never ties it to a clock implementation.
 */
interface Pause
{
    /**
     * Returns once that many seconds have passed; zero or less returns at once.
     */
    public function pause(int $seconds): void;
}
