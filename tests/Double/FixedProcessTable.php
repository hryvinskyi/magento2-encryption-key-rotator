<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessTable;

/**
 * A process list a test writes, or an unavailable one (null).
 */
final class FixedProcessTable implements ProcessTable
{
    /**
     * @param list<array{pid: int, ppid: int, elapsed: int|null, args: string}>|null $processes
     */
    public function __construct(
        private readonly ?array $processes,
    ) {}

    public function processes(): ?array
    {
        return $this->processes;
    }
}
