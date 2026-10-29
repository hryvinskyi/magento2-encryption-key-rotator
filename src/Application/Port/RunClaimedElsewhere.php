<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Another run holds the store's claim ({@see RunRegistry}): one unfinished run per Magento store, so a
 * second one, from any state directory, may not start.
 */
final class RunClaimedElsewhere extends \RuntimeException
{
    public function __construct(
        private readonly string $runId,
        private readonly string $stateDirectory,
    ) {
        parent::__construct(sprintf(
            'Run %s, kept in the state directory %s, holds this store: one unfinished run per store. Finish it there (retire and purge, or rollback and purge) before another run starts.',
            $runId,
            $stateDirectory,
        ));
    }

    public function runId(): string
    {
        return $this->runId;
    }

    public function stateDirectory(): string
    {
        return $this->stateDirectory;
    }
}
