<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * A column that holds, or may hold, encrypted values, with what discovery learned about it:
 * - the key columns that identify a row (empty when the table has none, and then the column is reported,
 *   never written);
 * - the table's columns updated automatically on every write (`ON UPDATE CURRENT_TIMESTAMP`), which a
 *   re-encryption assigns to themselves so that rewriting a ciphertext does not mark the row as changed
 *   for whatever syncs rows by their update time;
 * - how many values have the shape of a ciphertext, per key index;
 * - how many values hold a ciphertext inside a larger value;
 * - whether the database cut the scan short, in which case the counts are incomplete.
 *
 * Created through {@see ColumnCandidateFactory}.
 */
final class ColumnCandidate
{
    /**
     * @var array<int, int>
     */
    private readonly array $shapeCounts;

    /**
     * @param ColumnRef       $column             the column
     * @param list<string>    $rowKeyColumns      the key columns of its table, in key order, possibly empty
     * @param list<string>    $autoUpdatedColumns the table's columns updated automatically on every write
     * @param array<int, int> $shapeCounts        key index => values with the shape of a ciphertext under it
     * @param int             $embeddedCount      values holding a ciphertext inside a larger value
     * @param bool            $scanIncomplete     whether the database cut the scan short
     *
     * @throws InvalidValue when a count is negative, a key index is out of range, or a column name is empty
     */
    public function __construct(
        private readonly ColumnRef $column,
        private readonly array $rowKeyColumns,
        private readonly array $autoUpdatedColumns,
        array $shapeCounts,
        private readonly int $embeddedCount,
        private readonly bool $scanIncomplete,
    ) {
        foreach ([...$rowKeyColumns, ...$autoUpdatedColumns] as $name) {
            if ($name === '') {
                throw new InvalidValue(sprintf('A column of %s has an empty name.', $column->table()));
            }
        }
        foreach ($shapeCounts as $index => $count) {
            if ($index < 0 || $index > Ciphertext::MAX_KEY_INDEX || $count < 0) {
                throw new InvalidValue(sprintf('The shape counts of %s hold an index or count out of range.', $column->toString()));
            }
        }
        if ($embeddedCount < 0) {
            throw new InvalidValue(sprintf('The embedded count of %s cannot be negative.', $column->toString()));
        }
        ksort($shapeCounts);
        $this->shapeCounts = $shapeCounts;
    }

    public function column(): ColumnRef
    {
        return $this->column;
    }

    /**
     * @return list<string> the key columns of the table, in key order; empty when rows cannot be identified
     */
    public function rowKeyColumns(): array
    {
        return $this->rowKeyColumns;
    }

    /**
     * Whether rows can be identified, and so written.
     */
    public function hasRowKey(): bool
    {
        return $this->rowKeyColumns !== [];
    }

    /**
     * @return list<string> the table's columns updated automatically on every write
     */
    public function autoUpdatedColumns(): array
    {
        return $this->autoUpdatedColumns;
    }

    /**
     * @return array<int, int> key index => values with the shape of a ciphertext under it, in index order
     */
    public function shapeCounts(): array
    {
        return $this->shapeCounts;
    }

    public function shapeCountOn(int $index): int
    {
        return $this->shapeCounts[$index] ?? 0;
    }

    public function embeddedCount(): int
    {
        return $this->embeddedCount;
    }

    public function scanIncomplete(): bool
    {
        return $this->scanIncomplete;
    }
}
