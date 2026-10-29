<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see JournalEntry} values; implemented by the container build.
 */
#[CreatesInstancesOf(JournalEntry::class)]
interface JournalEntryFactory
{
    /**
     * @throws InvalidValue when the entry id is not positive
     */
    public function create(
        int $entryId,
        RunId $runId,
        ColumnRef $column,
        RowKey $rowKey,
        string $oldRaw,
        string $newRaw,
        Direction $direction,
    ): JournalEntry;
}
