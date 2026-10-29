<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * One journaled re-encryption: which run wrote what into which row, so the write can be undone by a
 * compare-and-swap of the new bytes back to the old ones.
 *
 * Created through {@see JournalEntryFactory}.
 */
final class JournalEntry
{
    /**
     * @param int       $entryId   the journal's own id of the entry
     * @param RunId     $runId     the run that wrote it
     * @param ColumnRef $column    the column
     * @param RowKey    $rowKey    the row
     * @param string    $oldRaw    the bytes the row held before
     * @param string    $newRaw    the bytes the run wrote
     * @param Direction $direction whether the run moved the value forward or back
     *
     * @throws InvalidValue when the entry id is not positive
     */
    public function __construct(
        private readonly int $entryId,
        private readonly RunId $runId,
        private readonly ColumnRef $column,
        private readonly RowKey $rowKey,
        private readonly string $oldRaw,
        private readonly string $newRaw,
        private readonly Direction $direction,
    ) {
        if ($entryId < 1) {
            throw new InvalidValue('A journal entry id is positive.');
        }
    }

    public function entryId(): int
    {
        return $this->entryId;
    }

    public function runId(): RunId
    {
        return $this->runId;
    }

    public function column(): ColumnRef
    {
        return $this->column;
    }

    public function rowKey(): RowKey
    {
        return $this->rowKey;
    }

    public function oldRaw(): string
    {
        return $this->oldRaw;
    }

    public function newRaw(): string
    {
        return $this->newRaw;
    }

    public function direction(): Direction
    {
        return $this->direction;
    }
}
