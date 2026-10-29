<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Counts the values of one column by shape, in the database: whole-value ciphertexts per key index in
 * one statement, and values holding a ciphertext inside a larger value in another.
 *
 * A server may stop a regular expression at its limits: MySQL's ICU engine at `regexp_time_limit` or
 * `regexp_stack_limit`, MariaDB's PCRE at its match limits, reachable by the unanchored embedded pattern
 * on a large text. Then the column's counts are reported as incomplete, never as clean.
 */
final class ShapeCounter
{
    /**
     * Server errors that mean "the regular expression hit a limit": MySQL 3698 (stack) and 3699 (time),
     * MariaDB 1139 (an error from the regular expression library).
     */
    private const REGEX_LIMIT_ERRORS = [3698, 3699, 1139];

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly TableStructure $structure,
        private readonly FetchedValues $values,
    ) {}

    /**
     * @param string $table  the table, without the prefix
     * @param string $column the column
     *
     * @return array{shapeCounts: array<int, int>, embedded: int, incomplete: bool}
     *
     * @throws \PDOException on any failure other than a regular expression limit
     */
    public function count(string $table, string $column): array
    {
        $quotedTable = $this->names->table($table);
        $subject = $this->structure->regexSubject($table, $column);
        $quotedColumn = $this->names->column($column);
        $shapeCounts = [];
        $embedded = 0;
        try {
            $shapes = $this->statements->run(sprintf(
                'SELECT CAST(SUBSTRING_INDEX(%s, \':\', 1) AS UNSIGNED) AS key_index, COUNT(*) AS values_count'
                . ' FROM %s WHERE %s REGEXP ? GROUP BY key_index',
                $quotedColumn,
                $quotedTable,
                $subject,
            ), [CiphertextPatterns::WHOLE_VALUE]);
            foreach ($this->values->all($shapes) as $row) {
                $shapeCounts[$this->values->int($row, 'key_index')] = $this->values->int($row, 'values_count');
            }
            $embeddedRows = $this->values->all($this->statements->run(sprintf(
                'SELECT COUNT(*) AS values_count FROM %1$s WHERE %2$s REGEXP ? AND %2$s NOT REGEXP ?',
                $quotedTable,
                $subject,
            ), [CiphertextPatterns::EMBEDDED, CiphertextPatterns::WHOLE_VALUE]));
            $embedded = $this->values->int($embeddedRows[0] ?? [], 'values_count');
        } catch (\PDOException $exception) {
            if (!in_array($exception->errorInfo[1] ?? null, self::REGEX_LIMIT_ERRORS, true)) {
                throw $exception;
            }

            return ['shapeCounts' => $shapeCounts, 'embedded' => $embedded, 'incomplete' => true];
        }

        return ['shapeCounts' => $shapeCounts, 'embedded' => $embedded, 'incomplete' => false];
    }
}
