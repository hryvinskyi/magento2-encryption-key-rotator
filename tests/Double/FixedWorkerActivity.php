<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;

/**
 * Worker activity that reports the processes a test gives it, with their start times.
 */
final class FixedWorkerActivity implements WorkerActivity
{
    /**
     * @param list<RunningProcess> $processes
     */
    public function __construct(
        private array $processes = [],
    ) {}

    public function running(): array
    {
        return $this->processes;
    }

    /**
     * Replaces the reported processes: a worker that starts or stops between two steps.
     *
     * @param list<RunningProcess> $processes
     */
    public function replace(array $processes): void
    {
        $this->processes = $processes;
    }

    /**
     * Adds a process that started at that moment, or at an unknown moment when null.
     */
    public function start(string $description, ?\DateTimeImmutable $startedAt): void
    {
        $this->processes[] = new RunningProcess($description, $startedAt);
    }
}
