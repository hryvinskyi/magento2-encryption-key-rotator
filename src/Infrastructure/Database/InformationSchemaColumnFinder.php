<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidateFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRefFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Psr\Clock\ClockInterface;

/**
 * Finds encrypted columns through the schema and the values themselves.
 *
 * A column is examined when it belongs to a base table of the current schema that carries the store's
 * table prefix, is not one of the tool's own tables (the journal, the record of the run holding the
 * store), is not left out by the scan scope, is not generated, and has a string type: `char`,
 * `varchar`, the `text` types, `binary`, `varbinary` or a `blob` type. A column declared shorter than
 * 40 characters is skipped: a ciphertext of even an empty value is longer.
 *
 * A column whose name the tool cannot put into a statement is reported with an incomplete scan and no
 * row key, so it is never written and never taken as clean.
 *
 * A column whose scan took longer than two seconds is named in the progress output with its time.
 */
final class InformationSchemaColumnFinder implements EncryptedColumnFinder
{
    private const TYPES = [
        'char', 'varchar', 'tinytext', 'text', 'mediumtext', 'longtext',
        'binary', 'varbinary', 'blob', 'mediumblob', 'longblob',
    ];
    private const SHORTEST_CIPHERTEXT = 40;
    private const SLOW_SCAN_SECONDS = 2.0;

    public function __construct(
        private readonly TableNames $names,
        private readonly TableStructure $structure,
        private readonly ShapeCounter $counter,
        private readonly FetchedValues $values,
        private readonly Statements $statements,
        private readonly ColumnRefFactory $columns,
        private readonly ColumnCandidateFactory $candidates,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    public function candidates(ScanScope $scope): array
    {
        $candidates = [];
        foreach ($this->examinedColumns() as ['table' => $table, 'column' => $column]) {
            $ref = $this->columns->create($table, $column);
            if ($scope->excludes($ref)) {
                continue;
            }
            if (!$this->names->isSupportedTable($table) || !$this->names->isSupported($column)) {
                $this->progress->warn(sprintf(
                    '%s has a name the tool does not put into a statement; it is reported as not scanned and is never written.',
                    $ref->toString(),
                ));
                $candidates[] = $this->candidates->create($ref, [], [], [], 0, true);

                continue;
            }
            $started = $this->clock->now();
            $counts = $this->counter->count($table, $column);
            $this->reportSlowScan($ref->toString(), $started);
            if ($counts['shapeCounts'] === [] && $counts['embedded'] === 0 && !$counts['incomplete']) {
                continue;
            }
            $candidates[] = $this->candidates->create(
                $ref,
                $this->structure->rowKey($table),
                $this->structure->autoUpdatedColumns($table),
                $counts['shapeCounts'],
                $counts['embedded'],
                $counts['incomplete'],
            );
        }

        return $candidates;
    }

    /**
     * @return list<array{table: string, column: string}> tables named without the prefix, in name order
     */
    private function examinedColumns(): array
    {
        $statement = $this->statements->run(
            'SELECT c.TABLE_NAME AS table_name, c.COLUMN_NAME AS column_name'
            . ' FROM information_schema.COLUMNS c'
            . ' JOIN information_schema.TABLES t ON t.TABLE_SCHEMA = c.TABLE_SCHEMA AND t.TABLE_NAME = c.TABLE_NAME'
            . ' WHERE c.TABLE_SCHEMA = DATABASE() AND t.TABLE_TYPE = \'BASE TABLE\''
            . ' AND LOWER(c.DATA_TYPE) IN (' . implode(', ', array_fill(0, count(self::TYPES), '?')) . ')'
            . ' AND c.CHARACTER_MAXIMUM_LENGTH >= ?'
            . ' AND COALESCE(c.GENERATION_EXPRESSION, \'\') = \'\''
            . ' ORDER BY c.TABLE_NAME, c.ORDINAL_POSITION',
            [...self::TYPES, self::SHORTEST_CIPHERTEXT],
        );
        $examined = [];
        foreach ($this->values->all($statement) as $row) {
            $table = $this->names->logical($this->values->string($row, 'table_name'));
            if ($table === null || in_array($table, [TableNames::JOURNAL, TableNames::RUN_REGISTRY], true)) {
                continue;
            }
            $examined[] = ['table' => $table, 'column' => $this->values->string($row, 'column_name')];
        }

        return $examined;
    }

    private function reportSlowScan(string $column, \DateTimeImmutable $started): void
    {
        $seconds = (float) $this->clock->now()->format('U.u') - (float) $started->format('U.u');
        if ($seconds > self::SLOW_SCAN_SECONDS) {
            $this->progress->step(sprintf('Scanning %s took %.1f s.', $column, $seconds));
        }
    }
}
