<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * What the tool needs to know about one of the store's tables, read from the schema once per table and
 * kept for the life of the process:
 * - the row key: the PRIMARY KEY columns in key order; otherwise the columns of the first UNIQUE index,
 *   by index name, whose columns are all NOT NULL; otherwise none, and then the table's rows are reported
 *   but never written;
 * - the columns the server updates on every write (`ON UPDATE CURRENT_TIMESTAMP`), which a rewrite
 *   assigns to themselves so the row does not look changed to whatever syncs rows by their update time;
 * - which columns are binary strings, which a regular expression only reads through a latin1 cast.
 *
 * Tables are named without the table prefix.
 */
final class TableStructure
{
    public const BINARY_TYPES = ['binary', 'varbinary', 'tinyblob', 'blob', 'mediumblob', 'longblob'];

    /**
     * @var array<string, array{exists: bool, columns: array<string, array{type: string, nullable: bool, autoUpdated: bool}>, rowKey: list<string>}>
     */
    private array $tables = [];

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly FetchedValues $values,
    ) {}

    public function exists(string $table): bool
    {
        return $this->structure($table)['exists'];
    }

    /**
     * @return list<string> the row key columns in key order; empty when rows cannot be identified
     */
    public function rowKey(string $table): array
    {
        return $this->structure($table)['rowKey'];
    }

    /**
     * @return list<string> the columns the server updates on every write of a row
     */
    public function autoUpdatedColumns(string $table): array
    {
        $columns = [];
        foreach ($this->structure($table)['columns'] as $name => $column) {
            if ($column['autoUpdated']) {
                $columns[] = $name;
            }
        }

        return $columns;
    }

    /**
     * The column as a regular expression may read it: the column itself, or for a binary string its
     * bytes as latin1 text. MySQL 8 refuses a binary string in every regular expression function, and
     * latin1 maps every byte, so no value fails the conversion and an ASCII ciphertext reads the same.
     * Both servers get the same expression.
     *
     * @throws UnsupportedIdentifier when the column name cannot be quoted
     * @throws \LogicException       when the table has no such column
     */
    public function regexSubject(string $table, string $column): string
    {
        $type = $this->structure($table)['columns'][$column]['type']
            ?? throw new \LogicException(sprintf('The table %s has no column %s.', $table, $column));
        $quoted = $this->names->column($column);

        return in_array($type, self::BINARY_TYPES, true) ? 'CAST(' . $quoted . ' AS CHAR CHARACTER SET latin1)' : $quoted;
    }

    /**
     * @return array{exists: bool, columns: array<string, array{type: string, nullable: bool, autoUpdated: bool}>, rowKey: list<string>}
     */
    private function structure(string $table): array
    {
        if (isset($this->tables[$table])) {
            return $this->tables[$table];
        }
        $physical = $this->names->physical($table);
        $columns = $this->columns($physical);

        return $this->tables[$table] = [
            'exists' => $columns !== [],
            'columns' => $columns,
            'rowKey' => $columns === [] ? [] : $this->chooseRowKey($physical, $columns),
        ];
    }

    /**
     * @return array<string, array{type: string, nullable: bool, autoUpdated: bool}>
     */
    private function columns(string $physical): array
    {
        $statement = $this->statements->run(
            'SELECT COLUMN_NAME AS column_name, LOWER(DATA_TYPE) AS data_type, IS_NULLABLE AS is_nullable, LOWER(EXTRA) AS extra'
            . ' FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? ORDER BY ORDINAL_POSITION',
            [$physical],
        );
        $columns = [];
        foreach ($this->values->all($statement) as $row) {
            $columns[$this->values->string($row, 'column_name')] = [
                'type' => $this->values->string($row, 'data_type'),
                'nullable' => $this->values->string($row, 'is_nullable') === 'YES',
                // MariaDB writes `on update current_timestamp()`, MySQL `DEFAULT_GENERATED on update CURRENT_TIMESTAMP`.
                'autoUpdated' => str_contains($this->values->nullableString($row, 'extra') ?? '', 'on update'),
            ];
        }

        return $columns;
    }

    /**
     * @param array<string, array{type: string, nullable: bool, autoUpdated: bool}> $columns
     *
     * @return list<string>
     */
    private function chooseRowKey(string $physical, array $columns): array
    {
        $statement = $this->statements->run(
            'SELECT INDEX_NAME AS index_name, NON_UNIQUE AS non_unique, COLUMN_NAME AS column_name'
            . ' FROM information_schema.STATISTICS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?'
            . ' ORDER BY INDEX_NAME = \'PRIMARY\' DESC, INDEX_NAME, SEQ_IN_INDEX',
            [$physical],
        );
        $indexes = [];
        foreach ($this->values->all($statement) as $row) {
            if ($this->values->int($row, 'non_unique') !== 0) {
                continue;
            }
            $name = $this->values->string($row, 'index_name');
            // A functional key part has no column: such an index cannot name a row by its columns.
            $indexes[$name][] = $this->values->nullableString($row, 'column_name');
        }
        foreach ($indexes as $name => $indexColumns) {
            $key = [];
            foreach ($indexColumns as $column) {
                if ($column === null || !isset($columns[$column]) || ($name !== 'PRIMARY' && $columns[$column]['nullable'])) {
                    continue 2;
                }
                $key[] = $column;
            }

            return $key;
        }

        return [];
    }
}
