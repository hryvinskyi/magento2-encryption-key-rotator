<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;

/**
 * The worker activity the tool asks: every source the container collects, one after another. Each
 * source sees the store's workers from its own side (the host's process list, the store's job
 * schedule), so their lists are concatenated, not merged.
 */
final class CompositeWorkerActivity implements WorkerActivity
{
    /**
     * @param iterable<WorkerActivity> $sources every worker activity the container collects, this one excluded
     */
    public function __construct(
        private readonly iterable $sources,
    ) {}

    public function running(): array
    {
        $running = [];
        foreach ($this->sources as $source) {
            array_push($running, ...$source->running());
        }

        return $running;
    }
}
