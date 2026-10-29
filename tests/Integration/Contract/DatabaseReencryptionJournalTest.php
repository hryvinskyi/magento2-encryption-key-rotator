<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\ReencryptionJournalContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TestDatabase;

/**
 * The database adapters keep the re-encryption and journal contract on a real server, under a table
 * prefix. The journal pages two entries at a time, so every case that reads pending entries crosses
 * batch boundaries.
 */
final class DatabaseReencryptionJournalTest extends ReencryptionJournalContractTestCase
{
    private const TABLE = 'contract_secret';

    private TestDatabase $database;

    private DatabaseAdapters $adapters;

    protected function setUp(): void
    {
        $this->database = TestDatabase::create('ct_');
        $this->adapters = new DatabaseAdapters($this->database->deploymentConfig(), journalBatchSize: 2);
        parent::setUp();
    }

    protected function tearDown(): void
    {
        $this->database->drop();
    }

    protected function writer(): ReencryptionWriter
    {
        return $this->adapters->writer;
    }

    protected function reverter(): JournalReverter
    {
        return $this->adapters->reverter;
    }

    protected function purger(): JournalPurger
    {
        return $this->adapters->purger;
    }

    protected function schema(): JournalSchema
    {
        return $this->adapters->schema;
    }

    protected function createSecretTable(): ColumnRef
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (id INT NOT NULL PRIMARY KEY, value TEXT NOT NULL)', $this->database->table(self::TABLE)));

        return new ColumnRef(self::TABLE, 'value');
    }

    protected function insertSecret(int $id, string $value): void
    {
        $this->database->connection()->prepare(sprintf('INSERT INTO `%s` (id, value) VALUES (?, ?)', $this->database->table(self::TABLE)))->execute([$id, $value]);
    }

    protected function changeSecret(int $id, string $value): void
    {
        $this->database->connection()->prepare(sprintf('UPDATE `%s` SET value = ? WHERE id = ?', $this->database->table(self::TABLE)))->execute([$value, $id]);
    }

    protected function deleteSecret(int $id): void
    {
        $this->database->connection()->prepare(sprintf('DELETE FROM `%s` WHERE id = ?', $this->database->table(self::TABLE)))->execute([$id]);
    }

    protected function secret(int $id): ?string
    {
        $value = $this->database->value(sprintf('SELECT value FROM `%s` WHERE id = ?', $this->database->table(self::TABLE)), [$id]);

        return is_string($value) ? $value : null;
    }
}
