<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The store's database in memory: tables of rows over PHP arrays, and the tool's journal.
 *
 * Every port it implements behaves as the real database adapters must:
 * - discovery counts values by the same two shapes the database scan uses (a whole-value ciphertext,
 *   and a ciphertext embedded in a larger value) and honours the scan scope;
 * - rows are paged by row key, each batch starting after the last key of the previous one;
 * - a write is a compare-and-swap on the exact old bytes, journaled when applied and never when it
 *   conflicts; a journal entry stays pending until it is reverted or superseded.
 *
 * A test plays the store's application with {@see update()} and {@see delete()}, and reaches between a
 * use case's read and its write with {@see beforeEachWrite()}.
 *
 * @phpstan-type Row array<string, int|string|null>
 * @phpstan-type Table array{rowKey: list<string>, columns: list<string>, autoUpdated: list<string>, rows: list<Row>}
 * @phpstan-type JournalRow array{entryId: int, runId: string, table: string, column: string, rowKey: RowKey, old: string, new: string, direction: Direction, settled: bool}
 */
final class InMemoryDatabase implements EncryptedColumnFinder, CiphertextRows, ReencryptionWriter, JournalReverter, JournalPurger, JournalSchema
{
    private const CIPHERTEXT_SHAPE = '~^([0-9]{1,3}):[0-9]:[A-Za-z0-9+/]{20,}={0,2}$~D';
    private const EMBEDDED_SHAPE = '~[0-9]{1,3}:[0-9]:([A-Za-z0-9+/]|\\\\/){40,}~';

    /**
     * @var array<string, Table>
     */
    private array $tables = [];

    /**
     * @var array<string, true> `table.column` of columns whose scan the database cuts short
     */
    private array $incomplete = [];

    /**
     * @var list<JournalRow>
     */
    private array $journal = [];

    private bool $journalExists = false;

    private int $nextEntryId = 1;

    private ?\Closure $beforeEachWrite = null;

    public function __construct(
        private readonly int $journalBatchSize = 100,
        private readonly ?CallLog $log = null,
    ) {}

    /**
     * Creates a table.
     *
     * @param list<string> $rowKeyColumns      the key columns, in key order; empty for a table without a key
     * @param list<string> $valueColumns       the other columns that hold text
     * @param list<string> $autoUpdatedColumns columns the database updates on every write of a row
     */
    public function createTable(string $table, array $rowKeyColumns, array $valueColumns, array $autoUpdatedColumns = []): void
    {
        $this->tables[$table] = [
            'rowKey' => $rowKeyColumns,
            'columns' => $valueColumns,
            'autoUpdated' => $autoUpdatedColumns,
            'rows' => [],
        ];
    }

    /**
     * Inserts a row.
     *
     * @param Row $row column => value
     */
    public function insert(string $table, array $row): void
    {
        $definition = $this->table($table);
        $definition['rows'][] = $row;
        $this->tables[$table] = $definition;
    }

    /**
     * Plays the store's application changing a value, outside the journal. Automatically updated columns
     * change as the database would change them.
     *
     * @param array<string, int|string> $key key column => value
     */
    public function update(string $table, array $key, string $column, ?string $value): void
    {
        $position = $this->position($table, $key) ?? throw new \LogicException(sprintf('No row %s in %s.', json_encode($key), $table));
        $definition = $this->table($table);
        $row = $definition['rows'][$position];
        $row[$column] = $value;
        foreach ($definition['autoUpdated'] as $autoUpdated) {
            $current = $row[$autoUpdated] ?? 0;
            $row[$autoUpdated] = is_int($current) ? $current + 1 : $current . '+';
        }
        $definition['rows'][$position] = $row;
        $this->tables[$table] = $definition;
    }

    /**
     * Plays the store's application deleting a row.
     *
     * @param array<string, int|string> $key key column => value
     */
    public function delete(string $table, array $key): void
    {
        $position = $this->position($table, $key);
        if ($position !== null) {
            array_splice($this->tables[$table]['rows'], $position, 1);
        }
    }

    /**
     * @param array<string, int|string> $key key column => value
     *
     * @return int|string|null the value, or null when the row or the value is absent
     */
    public function value(string $table, array $key, string $column): int|string|null
    {
        $position = $this->position($table, $key);

        return $position === null ? null : ($this->tables[$table]['rows'][$position][$column] ?? null);
    }

    /**
     * @return list<Row> the table's rows
     */
    public function rows(string $table): array
    {
        return $this->table($table)['rows'];
    }

    /**
     * Makes the scan of a column stop short, as the database does when a regular expression exceeds its
     * limits.
     */
    public function cutScanShort(string $table, string $column): void
    {
        $this->incomplete[$table . '.' . $column] = true;
    }

    /**
     * Runs before every compare-and-swap of a write, revert or supersede, with the database and the
     * table, row key and column about to be written: the place to change a row after it was read and
     * before it is written. Null removes the hook.
     *
     * @param (\Closure(self, ColumnRef, RowKey): void)|null $hook
     */
    public function beforeEachWrite(?\Closure $hook): void
    {
        $this->beforeEachWrite = $hook;
    }

    public function journalExists(): bool
    {
        return $this->journalExists;
    }

    /**
     * @return list<JournalEntry> every journal entry, settled or not, of every run or of one, oldest first
     */
    public function journalEntries(?RunId $runId = null): array
    {
        $entries = [];
        foreach ($this->journal as $row) {
            if ($runId === null || $row['runId'] === $runId->toString()) {
                $entries[] = $this->entry($row);
            }
        }

        return $entries;
    }

    public function candidates(ScanScope $scope): array
    {
        $candidates = [];
        foreach ($this->tables as $name => $table) {
            foreach ($table['columns'] as $column) {
                $ref = new ColumnRef($name, $column);
                if ($scope->excludes($ref)) {
                    continue;
                }
                $shapeCounts = [];
                $embedded = 0;
                foreach ($table['rows'] as $row) {
                    $value = $row[$column] ?? null;
                    if (!is_string($value)) {
                        continue;
                    }
                    if (preg_match(self::CIPHERTEXT_SHAPE, $value, $match) === 1) {
                        $index = (int) $match[1];
                        $shapeCounts[$index] = ($shapeCounts[$index] ?? 0) + 1;
                    } elseif (preg_match(self::EMBEDDED_SHAPE, $value) === 1) {
                        $embedded++;
                    }
                }
                $incomplete = isset($this->incomplete[$name . '.' . $column]);
                if ($shapeCounts === [] && $embedded === 0 && !$incomplete) {
                    continue;
                }
                $candidates[] = new ColumnCandidate($ref, $table['rowKey'], $table['autoUpdated'], $shapeCounts, $embedded, $incomplete);
            }
        }

        return $candidates;
    }

    public function batches(ColumnRef $column, int $keyIndex, int $batchSize): iterable
    {
        if ($batchSize < 1) {
            throw new \InvalidArgumentException('A batch holds at least one value.');
        }
        $table = $this->table($column->table());
        if ($table['rowKey'] === []) {
            throw new \LogicException(sprintf('%s has no row key; its rows cannot be paged.', $column->table()));
        }
        $prefix = $keyIndex . ':';
        $after = null;
        while (true) {
            $matching = [];
            foreach ($this->table($column->table())['rows'] as $row) {
                $value = $row[$column->column()] ?? null;
                $key = $this->keyOf($column->table(), $row);
                if (!is_string($value) || !str_starts_with($value, $prefix) || ($after !== null && $this->compareKeys($key, $after) <= 0)) {
                    continue;
                }
                $matching[] = new StoredValue($key, $value);
            }
            if ($matching === []) {
                return;
            }
            usort($matching, fn(StoredValue $a, StoredValue $b): int => $this->compareKeys($a->rowKey(), $b->rowKey()));
            $batch = array_slice($matching, 0, $batchSize);
            yield $batch;
            $after = $batch[count($batch) - 1]->rowKey();
        }
    }

    public function apply(RunId $runId, Direction $direction, array $reencryptions): WriteResult
    {
        $this->requireJournal();
        $applied = 0;
        $conflicts = [];
        foreach ($reencryptions as $reencryption) {
            $conflict = $this->compareAndSwap($reencryption->column(), $reencryption->rowKey(), $reencryption->oldRaw(), $reencryption->new()->toString());
            if ($conflict !== null) {
                $conflicts[] = $conflict;

                continue;
            }
            $this->journalWrite($runId->toString(), $reencryption->column(), $reencryption->rowKey(), $reencryption->oldRaw(), $reencryption->new()->toString(), $direction);
            $applied++;
        }
        $this->log?->record(sprintf('db.apply %s %d', $direction->value, $applied));

        return new WriteResult($applied, $conflicts);
    }

    public function pending(RunId $runId): iterable
    {
        $this->requireJournal();
        $after = 0;
        while (true) {
            $batch = [];
            foreach ($this->journal as $row) {
                if ($row['runId'] !== $runId->toString() || $row['direction'] !== Direction::Forward || $row['settled'] || $row['entryId'] <= $after) {
                    continue;
                }
                $batch[] = $this->entry($row);
                if (count($batch) === $this->journalBatchSize) {
                    break;
                }
            }
            if ($batch === []) {
                return;
            }
            yield $batch;
            $after = $batch[count($batch) - 1]->entryId();
        }
    }

    public function revert(array $entries): WriteResult
    {
        $this->requireJournal();
        $applied = 0;
        $conflicts = [];
        foreach ($entries as $entry) {
            $conflict = $this->compareAndSwap($entry->column(), $entry->rowKey(), $entry->newRaw(), $entry->oldRaw());
            if ($conflict !== null) {
                $conflicts[] = $conflict;

                continue;
            }
            $this->settle($entry);
            $applied++;
        }
        $this->log?->record(sprintf('db.revert %d', $applied));

        return new WriteResult($applied, $conflicts);
    }

    public function supersede(JournalEntry $entry, Reencryption $back): WriteResult
    {
        $this->requireJournal();
        if (!$entry->column()->equals($back->column()) || !$entry->rowKey()->equals($back->rowKey())) {
            throw new \LogicException('A back re-encryption supersedes the entry of its own row only.');
        }
        $this->log?->record('db.supersede');
        $conflict = $this->compareAndSwap($back->column(), $back->rowKey(), $back->oldRaw(), $back->new()->toString());
        if ($conflict !== null) {
            return new WriteResult(0, [$conflict]);
        }
        $this->journalWrite($entry->runId()->toString(), $back->column(), $back->rowKey(), $back->oldRaw(), $back->new()->toString(), Direction::Back);
        $this->settle($entry);

        return new WriteResult(1, []);
    }

    public function purge(RunId $runId): int
    {
        $before = count($this->journal);
        $this->journal = array_values(array_filter($this->journal, static fn(array $row): bool => $row['runId'] !== $runId->toString()));
        if ($this->journal === []) {
            $this->journalExists = false;
        }
        $this->log?->record('db.purge ' . $runId->toString());

        return $before - count($this->journal);
    }

    public function ensure(): void
    {
        $this->journalExists = true;
    }

    /**
     * Writes the new bytes where the row holds exactly the expected ones.
     *
     * @return Conflict|null the conflict, or null when the value was written
     */
    private function compareAndSwap(ColumnRef $column, RowKey $rowKey, string $expected, string $new): ?Conflict
    {
        if ($this->beforeEachWrite !== null) {
            ($this->beforeEachWrite)($this, $column, $rowKey);
        }
        $position = $this->position($column->table(), $this->plainKey($rowKey));
        if ($position === null) {
            return new Conflict($column, $rowKey, ConflictReason::Missing);
        }
        if (($this->tables[$column->table()]['rows'][$position][$column->column()] ?? null) !== $expected) {
            return new Conflict($column, $rowKey, ConflictReason::Changed);
        }
        $definition = $this->table($column->table());
        $definition['rows'][$position][$column->column()] = $new;
        $this->tables[$column->table()] = $definition;

        return null;
    }

    private function journalWrite(string $runId, ColumnRef $column, RowKey $rowKey, string $old, string $new, Direction $direction): void
    {
        $this->journal[] = [
            'entryId' => $this->nextEntryId++,
            'runId' => $runId,
            'table' => $column->table(),
            'column' => $column->column(),
            'rowKey' => $rowKey,
            'old' => $old,
            'new' => $new,
            'direction' => $direction,
            'settled' => false,
        ];
    }

    private function settle(JournalEntry $entry): void
    {
        foreach ($this->journal as $position => $row) {
            if ($row['entryId'] === $entry->entryId()) {
                $this->journal[$position]['settled'] = true;
            }
        }
    }

    /**
     * @param JournalRow $row
     */
    private function entry(array $row): JournalEntry
    {
        return new JournalEntry(
            $row['entryId'],
            new RunId($row['runId']),
            new ColumnRef($row['table'], $row['column']),
            $row['rowKey'],
            $row['old'],
            $row['new'],
            $row['direction'],
        );
    }

    private function requireJournal(): void
    {
        if (!$this->journalExists) {
            throw new \LogicException('The journal does not exist; ensure the journal schema first.');
        }
    }

    /**
     * @return Table
     */
    private function table(string $table): array
    {
        return $this->tables[$table] ?? throw new \LogicException(sprintf('No table %s.', $table));
    }

    /**
     * @param array<string, int|string> $key
     */
    private function position(string $table, array $key): ?int
    {
        foreach ($this->table($table)['rows'] as $position => $row) {
            $matches = true;
            foreach ($key as $column => $value) {
                if (($row[$column] ?? null) !== $value) {
                    $matches = false;
                    break;
                }
            }
            if ($matches) {
                return $position;
            }
        }

        return null;
    }

    /**
     * @param Row $row
     */
    private function keyOf(string $table, array $row): RowKey
    {
        $key = [];
        foreach ($this->table($table)['rowKey'] as $column) {
            $value = $row[$column] ?? null;
            if ($value === null) {
                throw new \LogicException(sprintf('A row of %s has no value in its key column %s.', $table, $column));
            }
            $key[$column] = $value;
        }

        return new RowKey($key);
    }

    /**
     * @return array<string, int|string>
     */
    private function plainKey(RowKey $rowKey): array
    {
        $key = [];
        foreach ($rowKey->values() as $column => $value) {
            $key[$column] = is_int($value) || is_string($value) ? $value : throw new \LogicException('The in-memory database keys rows by integers and strings.');
        }

        return $key;
    }

    /**
     * Orders row keys as the database orders them: column by column, numbers numerically, strings
     * byte by byte.
     */
    private function compareKeys(RowKey $a, RowKey $b): int
    {
        $right = $b->values();
        foreach ($a->values() as $column => $value) {
            $other = $right[$column] ?? null;
            $order = is_int($value) && is_int($other) ? $value <=> $other : strcmp((string) $value, (string) $other);
            if ($order !== 0) {
                return $order;
            }
        }

        return 0;
    }
}
