<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Writes re-encrypted values by compare-and-swap, journaling each write.
 *
 * A row is written only when its value is still exactly the old bytes; otherwise it is left alone and
 * reported as a conflict. Every applied write gets a journal entry (run, column, row, old and new bytes,
 * direction) in the same transaction, and a conflict gets none. The table's automatically updated columns
 * keep their values. {@see JournalSchema::ensure()} has run before the first call.
 */
interface ReencryptionWriter
{
    /**
     * Applies the batch in one transaction.
     *
     * @param list<Reencryption> $reencryptions
     */
    public function apply(RunId $runId, Direction $direction, array $reencryptions): WriteResult;
}
