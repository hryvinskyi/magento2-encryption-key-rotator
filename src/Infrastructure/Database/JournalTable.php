<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;

/**
 * The journal: one row per value the tool rewrote, `<prefix>encryption_key_rotation_journal`.
 *
 * - `row_key` is the row's key as JSON text, not the JSON type, which the two servers store differently;
 * - `old_value` and `new_value` are the exact bytes, as binary strings;
 * - `direction` tells a forward write from a write back to the key active before the run;
 * - `reverted_at` is set once a forward entry is reverted or superseded, and only pending entries
 *   (forward, `reverted_at` null) are ever undone.
 *
 * Every column has a type Magento's declarative schema can read. Magento reads the definition of every
 * table in the database on `setup:upgrade` and `setup:db:status`, and one column it cannot read, an
 * ENUM for instance, stops both for the whole store.
 */
final class JournalTable implements JournalSchema
{
    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly FetchedValues $values,
    ) {}

    public function ensure(): void
    {
        $this->create();
        $this->convertEnumDirection();
    }

    private function create(): void
    {
        $this->statements->define(sprintf(
            'CREATE TABLE IF NOT EXISTS %s ('
            . 'entry_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,'
            . ' run_id CHAR(32) NOT NULL,'
            . ' table_name VARCHAR(64) NOT NULL,'
            . ' column_name VARCHAR(64) NOT NULL,'
            . ' row_key TEXT NOT NULL,'
            . ' old_value LONGBLOB NOT NULL,'
            . ' new_value LONGBLOB NOT NULL,'
            . ' direction VARCHAR(8) NOT NULL,'
            . ' reverted_at DATETIME NULL,'
            . ' created_at DATETIME NOT NULL,'
            . ' KEY run_reverted (run_id, reverted_at)'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
            $this->names->journal(),
        ));
    }

    /**
     * Release 1.0.1 created `direction` as an ENUM; the values it holds fit the VARCHAR unchanged.
     */
    private function convertEnumDirection(): void
    {
        $rows = $this->values->all($this->statements->run(
            'SELECT COUNT(*) AS enum_count FROM information_schema.COLUMNS'
            . ' WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ? AND DATA_TYPE = ?',
            [$this->names->physical(TableNames::JOURNAL), 'direction', 'enum'],
        ));
        if ($this->values->int($rows[0] ?? [], 'enum_count') === 0) {
            return;
        }
        $this->statements->define(sprintf('ALTER TABLE %s MODIFY direction VARCHAR(8) NOT NULL', $this->names->journal()));
    }

    /**
     * Whether the journal table exists now.
     */
    public function exists(): bool
    {
        $rows = $this->values->all($this->statements->run(
            'SELECT COUNT(*) AS tables_count FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            [$this->names->physical(TableNames::JOURNAL)],
        ));

        return $this->values->int($rows[0] ?? [], 'tables_count') > 0;
    }

    /**
     * Drops the journal table when it holds no entry of any run.
     */
    public function dropWhenEmpty(): void
    {
        if (!$this->exists() || $this->values->positional($this->statements->run(sprintf('SELECT 1 FROM %s LIMIT 1', $this->names->journal()))) !== []) {
            return;
        }
        $this->statements->define(sprintf('DROP TABLE IF EXISTS %s', $this->names->journal()));
    }
}
