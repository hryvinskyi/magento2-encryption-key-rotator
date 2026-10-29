<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRefFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntryFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Reads and writes the journal's rows, inside the caller's transaction where one is open.
 *
 * Entries are inserted several rows per statement, in chunks small enough for the server's packet limit
 * whatever the size of the values.
 */
final class JournalRows
{
    private const ROWS_PER_INSERT = 100;
    private const BYTES_PER_INSERT = 1_048_576;

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly FetchedValues $values,
        private readonly ColumnRefFactory $columns,
        private readonly RowKeyFactory $rowKeys,
        private readonly JournalEntryFactory $entries,
    ) {}

    /**
     * Journals the writes that were applied.
     *
     * @param list<Reencryption> $applied
     */
    public function record(RunId $runId, Direction $direction, array $applied): void
    {
        $chunk = [];
        $bytes = 0;
        foreach ($applied as $reencryption) {
            $chunk[] = $reencryption;
            $bytes += strlen($reencryption->oldRaw()) + strlen($reencryption->new()->toString());
            if (count($chunk) === self::ROWS_PER_INSERT || $bytes >= self::BYTES_PER_INSERT) {
                $this->insert($runId, $direction, $chunk);
                $chunk = [];
                $bytes = 0;
            }
        }
        if ($chunk !== []) {
            $this->insert($runId, $direction, $chunk);
        }
    }

    /**
     * Locks a journal entry for the rest of the transaction and tells whether it is still pending.
     *
     * @return bool false when the entry is gone or already reverted or superseded
     */
    public function lockPending(int $entryId): bool
    {
        $rows = $this->values->all($this->statements->run(
            sprintf('SELECT reverted_at FROM %s WHERE entry_id = ? FOR UPDATE', $this->names->journal()),
            [$entryId],
        ));

        return $rows !== [] && $this->values->nullableString($rows[0], 'reverted_at') === null;
    }

    /**
     * Marks a forward entry reverted or superseded, so it is never undone again.
     */
    public function settle(int $entryId): void
    {
        $this->statements->run(
            sprintf('UPDATE %s SET reverted_at = UTC_TIMESTAMP() WHERE entry_id = ? AND reverted_at IS NULL', $this->names->journal()),
            [$entryId],
        );
    }

    /**
     * The run's pending forward entries after that entry id, oldest first.
     *
     * @return list<JournalEntry>
     */
    public function pendingAfter(RunId $runId, int $afterEntryId, int $limit): array
    {
        $rows = $this->values->all($this->statements->run(
            sprintf(
                'SELECT entry_id, table_name, column_name, row_key, old_value, new_value FROM %s'
                . ' WHERE run_id = ? AND reverted_at IS NULL AND direction = ? AND entry_id > ?'
                . ' ORDER BY entry_id LIMIT ?',
                $this->names->journal(),
            ),
            [$runId->toString(), Direction::Forward->value, $afterEntryId, $limit],
        ));
        $entries = [];
        foreach ($rows as $row) {
            $entries[] = $this->entries->create(
                $this->values->int($row, 'entry_id'),
                $runId,
                $this->columns->create($this->values->string($row, 'table_name'), $this->values->string($row, 'column_name')),
                $this->rowKeys->create($this->decodeRowKey($this->values->string($row, 'row_key'))),
                $this->values->string($row, 'old_value'),
                $this->values->string($row, 'new_value'),
                Direction::Forward,
            );
        }

        return $entries;
    }

    /**
     * @param non-empty-list<Reencryption> $chunk
     */
    private function insert(RunId $runId, Direction $direction, array $chunk): void
    {
        $parameters = [];
        foreach ($chunk as $reencryption) {
            $parameters = [
                ...$parameters,
                $runId->toString(),
                $reencryption->column()->table(),
                $reencryption->column()->column(),
                $reencryption->rowKey()->toJson(),
                $reencryption->oldRaw(),
                $reencryption->new()->toString(),
                $direction->value,
            ];
        }
        $this->statements->run(
            sprintf(
                'INSERT INTO %s (run_id, table_name, column_name, row_key, old_value, new_value, direction, created_at) VALUES %s',
                $this->names->journal(),
                implode(', ', array_fill(0, count($chunk), '(?, ?, ?, ?, ?, ?, ?, UTC_TIMESTAMP())')),
            ),
            $parameters,
        );
    }

    /**
     * @return array<string, int|float|string|bool>
     */
    private function decodeRowKey(string $json): array
    {
        $decoded = json_decode($json, true, 2, JSON_THROW_ON_ERROR);
        if (!is_array($decoded)) {
            throw new \UnexpectedValueException('A journaled row key is not a JSON object.');
        }
        $key = [];
        foreach ($decoded as $column => $value) {
            if (!is_int($value) && !is_float($value) && !is_string($value) && !is_bool($value)) {
                throw new \UnexpectedValueException('A journaled row key holds a value that cannot identify a row.');
            }
            $key[(string) $column] = $value;
        }

        return $key;
    }
}
