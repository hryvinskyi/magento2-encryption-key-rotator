<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKeyFactory;

/**
 * Writes the parts of a statement that name rows by their key: the equality that picks one row, the
 * keyset condition that starts after one, and the ordering; and reads a key back from fetched values.
 */
final class RowKeySql
{
    public function __construct(
        private readonly TableNames $names,
        private readonly FetchedValues $values,
        private readonly RowKeyFactory $rowKeys,
    ) {}

    /**
     * `k1 = ? AND k2 = ?`, with the key's values as parameters, in key order.
     *
     * @return array{sql: string, parameters: list<int|float|string|bool>}
     *
     * @throws UnsupportedIdentifier when a key column name cannot be quoted
     */
    public function equals(RowKey $rowKey): array
    {
        $conditions = [];
        $parameters = [];
        foreach ($rowKey->values() as $column => $value) {
            $conditions[] = $this->names->column($column) . ' = ?';
            $parameters[] = $value;
        }

        return ['sql' => implode(' AND ', $conditions), 'parameters' => $parameters];
    }

    /**
     * The rows after that key in key order: `k1 > ? OR (k1 = ? AND k2 > ?)`. The expanded form, rather
     * than a row-value comparison, lets both servers read the key's index as a range.
     *
     * @return array{sql: string, parameters: list<int|float|string|bool>}
     */
    public function after(RowKey $last): array
    {
        $terms = [];
        $parameters = [];
        $leading = [];
        $leadingParameters = [];
        foreach ($last->values() as $column => $value) {
            $quoted = $this->names->column($column);
            $terms[] = '(' . implode(' AND ', [...$leading, $quoted . ' > ?']) . ')';
            $parameters = [...$parameters, ...$leadingParameters, $value];
            $leading[] = $quoted . ' = ?';
            $leadingParameters[] = $value;
        }

        return ['sql' => '(' . implode(' OR ', $terms) . ')', 'parameters' => $parameters];
    }

    /**
     * The key columns, quoted and comma-separated, for a select list or an `ORDER BY`.
     *
     * @param list<string> $columns
     */
    public function columnList(array $columns): string
    {
        return implode(', ', array_map($this->names->column(...), $columns));
    }

    /**
     * The key of a fetched row whose first values are the key columns, in key order.
     *
     * @param list<string> $columns
     * @param list<mixed>  $row
     */
    public function read(array $columns, array $row): RowKey
    {
        $values = [];
        foreach ($columns as $position => $column) {
            $values[$column] = $this->values->keyValue($row[$position] ?? null, $column);
        }

        return $this->rowKeys->create($values);
    }
}
