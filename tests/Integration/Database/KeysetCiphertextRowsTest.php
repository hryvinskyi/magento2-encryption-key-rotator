<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableWithoutRowKey;

/**
 * Paging by row key: every value under the key index is yielded exactly once across batch boundaries,
 * in key order, composite keys and binary columns included, the same on both servers.
 */
final class KeysetCiphertextRowsTest extends DatabaseTestCase
{
    public function testEveryMatchingRowIsYieldedOnceAcrossBatchBoundaries(): void
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (config_id INT NOT NULL PRIMARY KEY, value TEXT NULL)', $this->database->table('core_config_data')));
        $expected = [];
        foreach ([9, 2, 7, 4, 5] as $id) {
            $value = $this->encrypt(1, 'value ' . $id)->toString();
            $this->insertRow('core_config_data', [$id, $value]);
            $expected[$id] = $value;
        }
        $this->insertRow('core_config_data', [3, $this->encrypt(0, 'other key')->toString()]);
        $this->insertRow('core_config_data', [6, $this->encrypt(11, 'index eleven starts with 1 too')->toString()]);
        $this->insertRow('core_config_data', [8, null]);
        ksort($expected);

        $batches = $this->batches(new ColumnRef('core_config_data', 'value'), 1, 2);

        self::assertSame([2, 2, 1], array_map('count', $batches));
        self::assertSame(array_map(static fn(int $id): string => sprintf('{"config_id":%d}', $id), array_keys($expected)), $this->keys($batches));
        self::assertSame(array_values($expected), $this->raws($batches));
    }

    public function testCompositeKeysArePagedInKeyOrder(): void
    {
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` (website_id SMALLINT NOT NULL, code VARCHAR(32) NOT NULL, secret TEXT NOT NULL, PRIMARY KEY (website_id, code))',
            $this->database->table('composite_secret'),
        ));
        foreach ([[1, 'b'], [0, 'c'], [1, 'a'], [0, 'a'], [2, 'a']] as [$website, $code]) {
            $this->insertRow('composite_secret', [$website, $code, $this->encrypt(2, $website . $code)->toString()]);
        }

        $batches = $this->batches(new ColumnRef('composite_secret', 'secret'), 2, 2);

        self::assertSame([
            '{"website_id":0,"code":"a"}',
            '{"website_id":0,"code":"c"}',
            '{"website_id":1,"code":"a"}',
            '{"website_id":1,"code":"b"}',
            '{"website_id":2,"code":"a"}',
        ], $this->keys($batches));
        foreach ($batches as $batch) {
            foreach ($batch as $value) {
                $key = $value->rowKey()->values();
                self::assertSame($key['website_id'] . $key['code'], $this->decrypt($value->raw()));
            }
        }
    }

    public function testBinaryAndBlobColumnsArePagedLikeText(): void
    {
        foreach (['binary_secret' => 'VARBINARY(255)', 'blob_secret' => 'BLOB'] as $table => $type) {
            $this->database->exec(sprintf('CREATE TABLE `%s` (id INT NOT NULL PRIMARY KEY, secret %s NULL)', $this->database->table($table), $type));
            $this->insertRow($table, [1, $this->encrypt(1, $table . ' one')->toString()]);
            $this->insertRow($table, [2, "\xff\xfe not text \x80"]);
            $this->insertRow($table, [3, $this->encrypt(1, $table . ' three')->toString()]);
            $this->insertRow($table, [4, $this->encrypt(1, $table . ' four')->toString()]);

            $batches = $this->batches(new ColumnRef($table, 'secret'), 1, 2);

            self::assertSame(['{"id":1}', '{"id":3}', '{"id":4}'], $this->keys($batches), $table);
            self::assertSame($table . ' four', $this->decrypt($batches[1][0]->raw()));
        }
    }

    public function testARowChangedBetweenBatchesIsNeitherSkippedNorRepeated(): void
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (id INT NOT NULL PRIMARY KEY, secret TEXT NULL)', $this->database->table('oauth_consumer')));
        foreach ([1, 2, 3, 4] as $id) {
            $this->insertRow('oauth_consumer', [$id, $this->encrypt(1, 'v' . $id)->toString()]);
        }
        $seen = [];

        foreach ($this->adapters->rows->batches(new ColumnRef('oauth_consumer', 'secret'), 1, 2) as $batch) {
            foreach ($batch as $value) {
                $seen[] = $value->rowKey()->toJson();
                // The store rewrites a row already read and one not read yet, both under the same key.
                $this->database->exec(sprintf('UPDATE `%s` SET secret = \'%s\' WHERE id IN (1, 4)', $this->database->table('oauth_consumer'), $this->encrypt(1, 'rewritten')->toString()));
            }
        }

        self::assertSame(['{"id":1}', '{"id":2}', '{"id":3}', '{"id":4}'], $seen);
    }

    public function testATableWithoutARowKeyCannotBePaged(): void
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (secret TEXT NULL)', $this->database->table('keyless_secret')));

        $this->expectException(TableWithoutRowKey::class);

        $this->batches(new ColumnRef('keyless_secret', 'secret'), 1, 2);
    }

    /**
     * @param list<int|string|null> $values
     */
    private function insertRow(string $table, array $values): void
    {
        $this->database->connection()->prepare(sprintf(
            'INSERT INTO `%s` VALUES (%s)',
            $this->database->table($table),
            implode(', ', array_fill(0, count($values), '?')),
        ))->execute($values);
    }

    /**
     * @param list<list<StoredValue>> $batches
     *
     * @return list<string>
     */
    private function keys(array $batches): array
    {
        return array_map(static fn(StoredValue $value): string => $value->rowKey()->toJson(), array_merge(...$batches));
    }

    /**
     * @param list<list<StoredValue>> $batches
     *
     * @return list<string>
     */
    private function raws(array $batches): array
    {
        return array_map(static fn(StoredValue $value): string => $value->raw(), array_merge(...$batches));
    }
}
