<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Undoes a run's journaled forward writes.
 *
 * An entry is pending until it is reverted or superseded; once it is, no later call yields it again, so
 * a rollback repeated after a crash neither retries nor reports it twice.
 */
interface JournalReverter
{
    /**
     * The run's forward entries that are still pending, oldest first.
     *
     * @return iterable<list<JournalEntry>> non-empty batches
     */
    public function pending(RunId $runId): iterable;

    /**
     * Puts each entry's old bytes back where the row still holds its new bytes, and marks the entry
     * reverted, in one transaction. An entry whose row holds anything else is a conflict and stays
     * pending.
     *
     * @param list<JournalEntry> $entries
     */
    public function revert(array $entries): WriteResult;

    /**
     * Settles an entry whose row was rewritten by the store after the run wrote it: in one transaction,
     * writes the back re-encryption by compare-and-swap, journals it (direction back), and marks the
     * forward entry superseded. On a compare-and-swap miss nothing changes and the result holds the
     * conflict.
     *
     * @param JournalEntry $entry the pending forward entry
     * @param Reencryption $back  the same row, from its current bytes to a value under the key that was
     *                            active before the run
     */
    public function supersede(JournalEntry $entry, Reencryption $back): WriteResult;
}
