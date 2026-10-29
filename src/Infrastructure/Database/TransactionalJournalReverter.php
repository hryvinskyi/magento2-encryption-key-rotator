<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Undoes journaled forward writes by compare-and-swap, the same byte comparison and timestamp
 * self-assignment the writer uses.
 *
 * Each entry is locked in the journal before its row is touched; an entry already reverted or
 * superseded, by an earlier call or a rollback that crashed after its commit, is skipped, so repeating a
 * revert changes nothing. A row that no longer holds the entry's new bytes is a conflict and its entry
 * stays pending.
 */
final class TransactionalJournalReverter implements JournalReverter
{
    public function __construct(
        private readonly TransactionRunner $transactions,
        private readonly CompareAndSwap $compareAndSwap,
        private readonly JournalRows $journal,
        private readonly WriteResultFactory $results,
        private readonly int $batchSize = 500,
    ) {}

    public function pending(RunId $runId): iterable
    {
        $after = 0;
        do {
            $batch = $this->journal->pendingAfter($runId, $after, $this->batchSize);
            if ($batch === []) {
                return;
            }
            yield $batch;
            $after = $batch[count($batch) - 1]->entryId();
        } while (count($batch) === $this->batchSize);
    }

    public function revert(array $entries): WriteResult
    {
        if ($entries === []) {
            return $this->results->create(0, []);
        }

        return $this->transactions->run(function () use ($entries): WriteResult {
            $applied = 0;
            $conflicts = [];
            foreach ($entries as $entry) {
                if (!$this->journal->lockPending($entry->entryId())) {
                    continue;
                }
                $conflict = $this->compareAndSwap->swap($entry->column(), $entry->rowKey(), $entry->newRaw(), $entry->oldRaw());
                if ($conflict !== null) {
                    $conflicts[] = $conflict;

                    continue;
                }
                $this->journal->settle($entry->entryId());
                $applied++;
            }

            return $this->results->create($applied, $conflicts);
        });
    }

    public function supersede(JournalEntry $entry, Reencryption $back): WriteResult
    {
        if (!$entry->column()->equals($back->column()) || !$entry->rowKey()->equals($back->rowKey())) {
            throw new \LogicException('A back re-encryption supersedes the entry of its own row only.');
        }

        return $this->transactions->run(function () use ($entry, $back): WriteResult {
            if (!$this->journal->lockPending($entry->entryId())) {
                return $this->results->create(0, []);
            }
            $conflict = $this->compareAndSwap->swap($back->column(), $back->rowKey(), $back->oldRaw(), $back->new()->toString());
            if ($conflict !== null) {
                return $this->results->create(0, [$conflict]);
            }
            $this->journal->record($entry->runId(), Direction::Back, [$back]);
            $this->journal->settle($entry->entryId());

            return $this->results->create(1, []);
        });
    }
}
