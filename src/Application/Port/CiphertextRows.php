<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;

/**
 * Reads the values of a column that start with a key index, batch by batch.
 *
 * Batches follow the table's row key in ascending order and each batch starts after the last row of the
 * previous one, so a row changed while the batches are read is neither skipped twice nor repeated, and
 * every row matching when its batch is read is yielded once.
 */
interface CiphertextRows
{
    /**
     * @param ColumnRef $column    a column whose table has a row key
     * @param int       $keyIndex  the key index the values start with (`<keyIndex>:`)
     * @param int       $batchSize the most values a batch holds, at least 1
     *
     * @return iterable<list<StoredValue>> non-empty batches
     */
    public function batches(ColumnRef $column, int $keyIndex, int $batchSize): iterable;
}
