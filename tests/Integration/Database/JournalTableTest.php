<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\MagentoReadableColumns;

/**
 * The tool's tables hold only columns Magento's schema reader can read, and a journal release 1.0.1
 * created with an ENUM column is brought to that shape with its entries intact.
 */
final class JournalTableTest extends DatabaseTestCase
{
    private const OTHER_RUN = 'fedcba9876543210fedcba9876543210';

    public function testTheToolsTablesHaveOnlyColumnsTheStoreCanRead(): void
    {
        $this->adapters->schema->ensure();
        $this->adapters->registry->claim($this->runId(), '/state');

        $columns = $this->database->select(
            'SELECT TABLE_NAME AS table_name, COLUMN_NAME AS column_name, DATA_TYPE AS data_type, COLUMN_TYPE AS column_type'
            . ' FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME IN (?, ?)',
            [$this->database->table('encryption_key_rotation_journal'), $this->database->table('encryption_key_rotation_run')],
        );

        self::assertCount(14, $columns, 'Both tables exist with all their columns.');
        foreach ($columns as $column) {
            $type = $column['data_type'] ?? null;
            $definition = $column['column_type'] ?? null;
            self::assertIsString($type);
            self::assertIsString($definition);
            self::assertContains(
                strtolower($definition),
                MagentoReadableColumns::DEFINITIONS[$type] ?? [],
                sprintf('%s.%s is a definition the store reads.', var_export($column['table_name'] ?? null, true), var_export($column['column_name'] ?? null, true)),
            );
        }
    }

    public function testEnsuringConvertsTheEnumDirectionOfRelease101AndKeepsTheEntries(): void
    {
        $this->createRelease101Journal();
        $this->insertEntry(self::RUN, 'forward', null);
        $this->insertEntry(self::RUN, 'back', '2026-10-30 07:00:00');

        $this->adapters->schema->ensure();

        self::assertSame('varchar(8)', $this->directionType());
        self::assertSame(
            [['direction' => 'forward', 'reverted_at' => null], ['direction' => 'back', 'reverted_at' => '2026-10-30 07:00:00']],
            $this->database->select(sprintf('SELECT direction, reverted_at FROM `%s` ORDER BY entry_id', $this->journalTable())),
        );
    }

    public function testEnsuringTwiceLeavesTheConvertedJournalAsItIs(): void
    {
        $this->createRelease101Journal();
        $this->insertEntry(self::RUN, 'forward', null);

        $this->adapters->schema->ensure();
        $this->adapters->schema->ensure();

        self::assertSame('varchar(8)', $this->directionType());
        self::assertSame(1, $this->journalRows());
    }

    public function testPurgingARunConvertsTheEnumJournalAnotherRunKeeps(): void
    {
        $this->createRelease101Journal();
        $this->insertEntry(self::RUN, 'forward', null);
        $this->insertEntry(self::OTHER_RUN, 'forward', null);

        self::assertSame(1, $this->adapters->purger->purge($this->runId()));

        self::assertTrue($this->adapters->schema->exists());
        self::assertSame('varchar(8)', $this->directionType());
        self::assertSame(1, $this->journalRows());
        self::assertSame(1, $this->adapters->purger->purge(new RunId(self::OTHER_RUN)));
    }

    /**
     * The journal exactly as release 1.0.1 created it.
     */
    private function createRelease101Journal(): void
    {
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` ('
            . 'entry_id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY,'
            . ' run_id CHAR(32) NOT NULL,'
            . ' table_name VARCHAR(64) NOT NULL,'
            . ' column_name VARCHAR(64) NOT NULL,'
            . ' row_key TEXT NOT NULL,'
            . ' old_value LONGBLOB NOT NULL,'
            . ' new_value LONGBLOB NOT NULL,'
            . ' direction ENUM(\'forward\', \'back\') NOT NULL,'
            . ' reverted_at DATETIME NULL,'
            . ' created_at DATETIME NOT NULL,'
            . ' KEY run_reverted (run_id, reverted_at)'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
            $this->journalTable(),
        ));
        self::assertSame("enum('forward','back')", $this->directionType());
    }

    private function insertEntry(string $runId, string $direction, ?string $revertedAt): void
    {
        $this->database->exec(sprintf(
            'INSERT INTO `%s` (run_id, table_name, column_name, row_key, old_value, new_value, direction, reverted_at, created_at)'
            . " VALUES ('%s', 'core_config_data', 'value', '{\"config_id\":1}', '0:3:old', '1:3:new', '%s', %s, '2026-10-30 06:43:00')",
            $this->journalTable(),
            $runId,
            $direction,
            $revertedAt === null ? 'NULL' : "'" . $revertedAt . "'",
        ));
    }

    private function directionType(): string
    {
        $type = $this->database->value(
            'SELECT COLUMN_TYPE FROM information_schema.COLUMNS WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ? AND COLUMN_NAME = ?',
            [$this->journalTable(), 'direction'],
        );

        return strtolower(is_string($type) ? $type : '');
    }

    private function journalTable(): string
    {
        return $this->database->table('encryption_key_rotation_journal');
    }
}
