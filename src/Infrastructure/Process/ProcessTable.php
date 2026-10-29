<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

/**
 * The processes running on this host, as the system's process list shows them.
 */
interface ProcessTable
{
    /**
     * Every process: its id, its parent's id, the seconds since it started (null when the process list
     * does not tell) and its command line.
     *
     * @return list<array{pid: int, ppid: int, elapsed: int|null, args: string}>|null null when the
     *                                                                                  process list cannot be read
     */
    public function processes(): ?array;
}
