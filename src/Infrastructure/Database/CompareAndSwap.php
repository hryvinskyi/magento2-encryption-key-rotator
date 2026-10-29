<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;

/**
 * Rewrites one value only where the row still holds exactly the expected bytes, inside the caller's
 * transaction:
 *
 *     UPDATE t SET c = ?, ts = ts WHERE <row key> AND CAST(c AS BINARY) = CAST(? AS BINARY)
 *
 * - The comparison is on bytes, so a case-insensitive or PAD SPACE collation never takes a different
 *   value for the expected one.
 * - Every column the server updates on every write is assigned to itself: an explicit assignment
 *   suppresses `ON UPDATE CURRENT_TIMESTAMP`, so a rewritten ciphertext does not make the row look
 *   changed to whatever exports or syncs rows by their update time.
 * - When nothing was updated, the row is read `FOR UPDATE` to tell a changed value from a row that is
 *   gone, and the lock keeps that answer true until the transaction ends.
 *
 * The row key must be exactly the table's row key, so the statement can never reach more than one row.
 */
final class CompareAndSwap
{
    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly TableStructure $structure,
        private readonly RowKeySql $rowKeySql,
        private readonly FetchedValues $values,
        private readonly ConflictFactory $conflicts,
    ) {}

    /**
     * @return Conflict|null the conflict, or null when the new bytes were written
     *
     * @throws TableWithoutRowKey when the row key is not the table's row key
     * @throws \PDOException      when a statement fails
     */
    public function swap(ColumnRef $column, RowKey $rowKey, string $expected, string $new): ?Conflict
    {
        $keyColumns = $this->structure->rowKey($column->table());
        if ($keyColumns === [] || $rowKey->columns() !== $keyColumns) {
            throw new TableWithoutRowKey(sprintf(
                'The row key %s does not name the row key of %s; the row is not written.',
                json_encode($rowKey->columns(), JSON_THROW_ON_ERROR),
                $column->table(),
            ));
        }
        $table = $this->names->table($column->table());
        $quotedColumn = $this->names->column($column->column());
        $assignments = [$quotedColumn . ' = ?'];
        foreach ($this->structure->autoUpdatedColumns($column->table()) as $autoUpdated) {
            $assignments[] = sprintf('%1$s = %1$s', $this->names->column($autoUpdated));
        }
        $where = $this->rowKeySql->equals($rowKey);
        $updated = $this->statements->run(
            sprintf(
                'UPDATE %s SET %s WHERE %s AND CAST(%s AS BINARY) = CAST(? AS BINARY)',
                $table,
                implode(', ', $assignments),
                $where['sql'],
                $quotedColumn,
            ),
            [$new, ...$where['parameters'], $expected],
        )->rowCount();
        if ($updated > 0) {
            return null;
        }
        $present = $this->values->positional($this->statements->run(
            sprintf('SELECT 1 FROM %s WHERE %s FOR UPDATE', $table, $where['sql']),
            $where['parameters'],
        ));

        return $this->conflicts->create($column, $rowKey, $present === [] ? ConflictReason::Missing : ConflictReason::Changed);
    }
}
