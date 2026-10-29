<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ReencryptionFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Undoes a run's forward writes from its journal.
 *
 * Every pending forward entry is put back by compare-and-swap: where the row still holds the bytes the
 * run wrote, it gets its exact bytes from before the run again. Where the store rewrote the row in
 * between:
 * - its value is a ciphertext under the new key: the store wrote it with the new ring, so it is
 *   re-encrypted onto the key that was active before the run, and the forward entry is settled in the
 *   same transaction, so a later rollback neither retries nor reports it;
 * - anything else (another key, a plain value, a deleted row): the store's newer value is kept, and the
 *   entry stays pending and is reported.
 *
 * Only pending entries are read, so running it again after an interruption touches nothing it already
 * settled.
 */
final class ForwardJournalReversal
{
    public function __construct(
        private readonly JournalReverter $journal,
        private readonly CiphertextRows $rows,
        private readonly CiphertextParser $parser,
        private readonly Cipher $cipher,
        private readonly ReencryptionFactory $reencryptions,
        private readonly JournalReversalOutcomeFactory $outcomes,
        private readonly Progress $progress,
    ) {}

    /**
     * @param RunId $runId       the run whose forward entries are undone
     * @param int   $newIndex    the index of the key the run appended
     * @param Key   $newKey      the key the run appended, as the run keeps it
     * @param int   $targetIndex the index of the key that was active before the run
     * @param Key   $targetKey   that key
     * @param int   $batchSize   the most values read at once when looking up rewritten rows, at least 1
     *
     * @throws InvalidValue    when the new index and the target index are the same
     * @throws RoundTripFailed when a new value does not decrypt back to its plaintext; it is not written
     */
    public function revert(RunId $runId, int $newIndex, Key $newKey, int $targetIndex, Key $targetKey, int $batchSize): JournalReversalOutcome
    {
        if ($newIndex === $targetIndex) {
            throw new InvalidValue(sprintf('The key index %d cannot be the new key and the target of the same reversal.', $newIndex));
        }

        $reverted = 0;
        /** @var list<array{entry: JournalEntry, conflict: Conflict}> $rewritten */
        $rewritten = [];
        foreach ($this->journal->pending($runId) as $batch) {
            $result = $this->journal->revert($batch);
            $reverted += $result->applied();
            foreach ($result->conflicts() as $conflict) {
                $entry = $this->entryOf($conflict, $batch);
                if ($entry !== null) {
                    $rewritten[] = ['entry' => $entry, 'conflict' => $conflict];
                }
            }
        }
        $this->progress->step(sprintf('Put %d values back to their bytes from before the run', $reverted));

        $superseded = 0;
        $leftAlone = [];
        foreach ($this->byColumn($rewritten) as $entries) {
            $column = $entries[0]['entry']->column();
            $unmatched = $entries;
            foreach ($this->rows->batches($column, $newIndex, $batchSize) as $values) {
                foreach ($values as $stored) {
                    $position = $this->positionOf($stored, $unmatched);
                    if ($position === null) {
                        continue;
                    }
                    $item = $unmatched[$position];
                    unset($unmatched[$position]);
                    $outcome = $this->supersede($item['entry'], $item['conflict'], $stored, $newKey, $targetIndex, $targetKey);
                    if ($outcome === null) {
                        $superseded++;
                    } else {
                        $leftAlone[] = $outcome;
                    }
                }
            }
            foreach ($unmatched as $left) {
                $leftAlone[] = $left['conflict'];
            }
        }
        if ($superseded > 0 || $leftAlone !== []) {
            $this->progress->step(sprintf(
                'Moved %d values the store rewrote under the new key back; left %d rewritten values alone',
                $superseded,
                count($leftAlone),
            ));
        }

        return $this->outcomes->create($reverted, $superseded, $leftAlone);
    }

    /**
     * Re-encrypts the row's current value onto the target key and settles the entry.
     *
     * @param Conflict $conflict the revert's conflict for the entry, kept when the value cannot be moved
     *
     * @return Conflict|null why the entry stays pending, or null when it was settled
     */
    private function supersede(JournalEntry $entry, Conflict $conflict, StoredValue $stored, Key $newKey, int $targetIndex, Key $targetKey): ?Conflict
    {
        $ciphertext = $this->parser->parse($stored->raw());
        $plaintext = $ciphertext === null || !$this->cipher->supports($ciphertext->cipherVersion())
            ? null
            : $this->cipher->decrypt($ciphertext, $newKey);
        if ($plaintext === null) {
            return $conflict;
        }

        $result = $this->journal->supersede($entry, $this->reencryptions->create(
            $entry->column(),
            $entry->rowKey(),
            $stored->raw(),
            $this->cipher->encrypt($plaintext, $targetIndex, $targetKey),
        ));

        return $result->conflicts()[0] ?? null;
    }

    /**
     * @param list<JournalEntry> $batch
     */
    private function entryOf(Conflict $conflict, array $batch): ?JournalEntry
    {
        foreach ($batch as $entry) {
            if ($entry->column()->equals($conflict->column()) && $entry->rowKey()->equals($conflict->rowKey())) {
                return $entry;
            }
        }

        return null;
    }

    /**
     * @param array<int, array{entry: JournalEntry, conflict: Conflict}> $entries
     */
    private function positionOf(StoredValue $stored, array $entries): ?int
    {
        foreach ($entries as $position => $candidate) {
            if ($candidate['entry']->rowKey()->equals($stored->rowKey())) {
                return $position;
            }
        }

        return null;
    }

    /**
     * @param list<array{entry: JournalEntry, conflict: Conflict}> $rewritten
     *
     * @return list<non-empty-list<array{entry: JournalEntry, conflict: Conflict}>> the entries grouped by column
     */
    private function byColumn(array $rewritten): array
    {
        $groups = [];
        foreach ($rewritten as $item) {
            $groups[$item['entry']->column()->toString()][] = $item;
        }

        return array_values($groups);
    }
}
