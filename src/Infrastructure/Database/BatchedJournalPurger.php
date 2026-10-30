<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Deletes a run's journal a thousand rows per statement, so no statement holds locks on the whole
 * journal, and drops the journal table once no run has an entry left.
 */
final class BatchedJournalPurger implements JournalPurger
{
    private const ROWS_PER_DELETE = 1000;

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly JournalTable $journal,
    ) {}

    public function purge(RunId $runId): int
    {
        if (!$this->journal->exists()) {
            return 0;
        }
        // Entries of other runs can keep the table: it leaves in the shape the store can read.
        $this->journal->ensure();
        $deleted = 0;
        do {
            $batch = $this->statements->run(
                sprintf('DELETE FROM %s WHERE run_id = ? ORDER BY entry_id LIMIT %d', $this->names->journal(), self::ROWS_PER_DELETE),
                [$runId->toString()],
            )->rowCount();
            $deleted += $batch;
        } while ($batch === self::ROWS_PER_DELETE);
        $this->journal->dropWhenEmpty();

        return $deleted;
    }
}
