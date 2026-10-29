<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValueFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;

/**
 * Pages the values of a column that start with a key index, by the table's row key: each batch is the
 * next rows in key order after the last key of the previous batch, so rows changed meanwhile are neither
 * skipped nor read twice. A binary column is matched through the same latin1 cast the scan uses.
 */
final class KeysetCiphertextRows implements CiphertextRows
{
    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly TableStructure $structure,
        private readonly RowKeySql $rowKeySql,
        private readonly CiphertextPatterns $patterns,
        private readonly FetchedValues $values,
        private readonly StoredValueFactory $storedValues,
    ) {}

    public function batches(ColumnRef $column, int $keyIndex, int $batchSize): iterable
    {
        if ($batchSize < 1) {
            throw new \InvalidArgumentException('A batch holds at least one value.');
        }
        $keyColumns = $this->structure->rowKey($column->table());
        if ($keyColumns === []) {
            throw new TableWithoutRowKey(sprintf('%s has no row key; its rows cannot be paged.', $column->table()));
        }
        $select = sprintf(
            'SELECT %s, %s FROM %s WHERE %s REGEXP ?',
            $this->rowKeySql->columnList($keyColumns),
            $this->names->column($column->column()),
            $this->names->table($column->table()),
            $this->structure->regexSubject($column->table(), $column->column()),
        );
        $order = ' ORDER BY ' . $this->rowKeySql->columnList($keyColumns) . ' LIMIT ?';
        $pattern = $this->patterns->underKeyIndex($keyIndex);
        $last = null;
        do {
            if ($last === null) {
                $rows = $this->statements->run($select . $order, [$pattern, $batchSize]);
            } else {
                $after = $this->rowKeySql->after($last);
                $rows = $this->statements->run($select . ' AND ' . $after['sql'] . $order, [$pattern, ...$after['parameters'], $batchSize]);
            }
            $batch = [];
            foreach ($this->values->positional($rows) as $row) {
                $raw = $row[count($keyColumns)] ?? null;
                if (!is_string($raw)) {
                    throw new \UnexpectedValueException(sprintf('A value of %s was not read as bytes.', $column->toString()));
                }
                $batch[] = $this->storedValues->create($this->rowKeySql->read($keyColumns, $row), $raw);
            }
            if ($batch === []) {
                return;
            }
            yield $batch;
            $last = $batch[count($batch) - 1]->rowKey();
        } while (count($batch) === $batchSize);
    }
}
