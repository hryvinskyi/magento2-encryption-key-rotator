<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Deletes a run's journal, which holds the run's old values: after it, the run can no longer be undone.
 */
interface JournalPurger
{
    /**
     * @return int the journal entries deleted
     */
    public function purge(RunId $runId): int;
}
