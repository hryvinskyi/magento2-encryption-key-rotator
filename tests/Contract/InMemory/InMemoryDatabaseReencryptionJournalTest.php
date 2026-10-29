<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract\InMemory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\ReencryptionJournalContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;

/**
 * The in-memory database keeps the re-encryption and journal contract. Its journal pages two entries at
 * a time, so every contract case that reads pending entries crosses batch boundaries.
 */
final class InMemoryDatabaseReencryptionJournalTest extends ReencryptionJournalContractTestCase
{
    private const TABLE = 'contract_secret';

    private ?InMemoryDatabase $database = null;

    protected function writer(): ReencryptionWriter
    {
        return $this->database();
    }

    protected function reverter(): JournalReverter
    {
        return $this->database();
    }

    protected function purger(): JournalPurger
    {
        return $this->database();
    }

    protected function schema(): JournalSchema
    {
        return $this->database();
    }

    protected function createSecretTable(): ColumnRef
    {
        $this->database()->createTable(self::TABLE, ['id'], ['value']);

        return new ColumnRef(self::TABLE, 'value');
    }

    protected function insertSecret(int $id, string $value): void
    {
        $this->database()->insert(self::TABLE, ['id' => $id, 'value' => $value]);
    }

    protected function changeSecret(int $id, string $value): void
    {
        $this->database()->update(self::TABLE, ['id' => $id], 'value', $value);
    }

    protected function deleteSecret(int $id): void
    {
        $this->database()->delete(self::TABLE, ['id' => $id]);
    }

    protected function secret(int $id): ?string
    {
        $value = $this->database()->value(self::TABLE, ['id' => $id], 'value');

        return $value === null ? null : (string) $value;
    }

    private function database(): InMemoryDatabase
    {
        return $this->database ??= new InMemoryDatabase(journalBatchSize: 2);
    }
}
