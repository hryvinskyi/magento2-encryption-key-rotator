<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntryFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectJournalEntryFactory implements JournalEntryFactory
{
    public function create(
        int $entryId,
        RunId $runId,
        ColumnRef $column,
        RowKey $rowKey,
        string $oldRaw,
        string $newRaw,
        Direction $direction,
    ): JournalEntry {
        return new JournalEntry($entryId, $runId, $column, $rowKey, $oldRaw, $newRaw, $direction);
    }
}
