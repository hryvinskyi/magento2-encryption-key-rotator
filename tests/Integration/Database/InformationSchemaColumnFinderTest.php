<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\AdvancingClock;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;

/**
 * Discovery on a schema shaped like a store's: the finder reports exactly the columns that hold
 * ciphertexts, with counts per key index, embedded counts, row keys and automatically updated columns,
 * the same on MariaDB and MySQL 8, binary columns included.
 */
final class InformationSchemaColumnFinderTest extends DatabaseTestCase
{
    public function testItReportsExactlyTheEncryptedColumnsWithTheirCountsAndKeys(): void
    {
        $this->seedStoreShapedSchema();

        $candidates = $this->candidates(new ScanScope([]));

        self::assertSame([
            'binary_secret.secret' => ['rowKey' => ['id'], 'auto' => [], 'shapes' => [1 => 1], 'embedded' => 0, 'incomplete' => false],
            'blob_secret.secret' => ['rowKey' => ['id'], 'auto' => [], 'shapes' => [1 => 1], 'embedded' => 1, 'incomplete' => false],
            'composite_secret.secret' => ['rowKey' => ['website_id', 'code'], 'auto' => [], 'shapes' => [1 => 3], 'embedded' => 0, 'incomplete' => false],
            'core_config_data.value' => ['rowKey' => ['config_id'], 'auto' => [], 'shapes' => [0 => 2, 1 => 4, 2 => 1], 'embedded' => 0, 'incomplete' => false],
            'customer_entity.rp_token' => ['rowKey' => ['entity_id'], 'auto' => ['updated_at'], 'shapes' => [1 => 2], 'embedded' => 0, 'incomplete' => false],
            'keyless_secret.secret' => ['rowKey' => [], 'auto' => [], 'shapes' => [1 => 1], 'embedded' => 0, 'incomplete' => false],
            'oauth_consumer.secret' => ['rowKey' => ['entity_id'], 'auto' => [], 'shapes' => [1 => 1], 'embedded' => 1, 'incomplete' => false],
            'payment_info.additional_information' => ['rowKey' => ['entity_id'], 'auto' => [], 'shapes' => [], 'embedded' => 2, 'incomplete' => false],
            'token_store.secret' => ['rowKey' => ['token_hash'], 'auto' => [], 'shapes' => [1 => 1], 'embedded' => 0, 'incomplete' => false],
        ], $candidates);
    }

    public function testExcludedTablesAndColumnsAreLeftOut(): void
    {
        $this->seedStoreShapedSchema();

        $candidates = $this->candidates(new ScanScope(['core_*', 'customer_entity.rp_token', '*_secret']));

        self::assertSame(['oauth_consumer.secret', 'payment_info.additional_information', 'token_store.secret'], array_keys($candidates));
    }

    public function testAColumnWithANameTheToolCannotQuoteIsReportedAsNotScannedAndUnwritable(): void
    {
        $this->database->exec(
            sprintf('CREATE TABLE `%s` (id INT NOT NULL PRIMARY KEY, secret TEXT)', $this->database->table('odd-name')),
            sprintf('INSERT INTO `%s` VALUES (1, \'%s\')', $this->database->table('odd-name'), $this->encrypt(1, 'x')->toString()),
        );

        $candidates = $this->candidates(new ScanScope([]));

        self::assertSame(['odd-name.secret' => ['rowKey' => [], 'auto' => [], 'shapes' => [], 'embedded' => 0, 'incomplete' => true]], $candidates);
        $progress = $this->adapters->progress;
        self::assertInstanceOf(RecordingProgress::class, $progress);
        self::assertCount(1, $progress->warnings());
        self::assertStringContainsString('odd-name.secret', $progress->warnings()[0]);
    }

    public function testAColumnWhoseScanTakesLongerThanTwoSecondsIsNamedWithItsTime(): void
    {
        $progress = new RecordingProgress();
        $adapters = new DatabaseAdapters(
            $this->database->deploymentConfig(),
            $progress,
            new AdvancingClock(new \DateTimeImmutable('2026-10-29T10:00:00+00:00'), new \DateInterval('PT3S')),
        );
        $this->createTable('oauth_consumer', 'entity_id INT NOT NULL PRIMARY KEY, secret VARCHAR(128)');
        $this->insert('oauth_consumer', [1, $this->encrypt(1, 'secret')->toString()]);

        $adapters->finder->candidates(new ScanScope([]));

        self::assertSame(['Scanning oauth_consumer.secret took 3.0 s.'], $progress->steps());
    }

    public function testAServerThatCutsTheRegularExpressionShortMarksTheColumnIncompleteNeverClean(): void
    {
        $this->createTable('payment_info', 'entity_id INT NOT NULL PRIMARY KEY, additional_information LONGTEXT');
        // Many near-matches make the unanchored pattern work hard at every position.
        $document = json_encode(['note' => str_repeat('1:2:' . str_repeat('A', 39) . '-', 40_000), 'token' => $this->encrypt(1, 'card')->toString()], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES);
        $this->insert('payment_info', [1, $document]);
        if (!$this->database->isMysql()) {
            // MariaDB's engine has no time limit this value reaches: the scan completes and counts it.
            self::assertSame(
                ['payment_info.additional_information' => ['rowKey' => ['entity_id'], 'auto' => [], 'shapes' => [], 'embedded' => 1, 'incomplete' => false]],
                $this->candidates(new ScanScope([])),
            );

            return;
        }
        $read = $this->database->server()->prepare('SELECT @@GLOBAL.regexp_time_limit');
        $read->execute();
        $limit = $read->fetchColumn();
        $this->database->server()->exec('SET GLOBAL regexp_time_limit = 1');
        try {
            $candidates = $this->candidates(new ScanScope([]));
        } finally {
            $this->database->server()->exec(sprintf('SET GLOBAL regexp_time_limit = %d', is_numeric($limit) ? (int) $limit : 32));
        }

        self::assertSame(
            ['payment_info.additional_information' => ['rowKey' => ['entity_id'], 'auto' => [], 'shapes' => [], 'embedded' => 0, 'incomplete' => true]],
            $candidates,
        );
    }

    /**
     * Tables shaped like a store's, under the prefix, with values under key indices 0, 1 and 2, a
     * value of cipher version 2, and the columns discovery must leave out.
     */
    private function seedStoreShapedSchema(): void
    {
        $this->createTable('core_config_data', 'config_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, path VARCHAR(255) NOT NULL, value TEXT NULL');
        $this->insert('core_config_data', [1, 'payment/a/key', $this->encrypt(0, 'zero a')->toString()]);
        $this->insert('core_config_data', [2, 'payment/b/key', $this->encrypt(0, 'zero b')->toString()]);
        $this->insert('core_config_data', [3, 'payment/c/key', $this->encrypt(1, 'one a')->toString()]);
        $this->insert('core_config_data', [4, 'payment/d/key', $this->encrypt(1, 'one b')->toString()]);
        $this->insert('core_config_data', [5, 'payment/e/key', $this->encrypt(1, '')->toString()]);
        $this->insert('core_config_data', [6, 'payment/f/key', $this->encrypt(2, 'two')->toString()]);
        $this->insert('core_config_data', [7, 'payment/g/key', '1:2:' . base64_encode(random_bytes(40))]);
        $this->insert('core_config_data', [8, 'web/unsecure/base_url', 'https://store.example/']);
        $this->insert('core_config_data', [9, 'general/locale/code', null]);

        $this->createTable('customer_entity', 'entity_id INT UNSIGNED NOT NULL PRIMARY KEY, email VARCHAR(255) NOT NULL, rp_token VARCHAR(128) NULL,'
            . ' updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP');
        $this->insert('customer_entity', [1, 'a@example.test', $this->encrypt(1, 'token a')->toString(), '2020-01-01 00:00:00']);
        $this->insert('customer_entity', [2, 'b@example.test', $this->encrypt(1, 'token b')->toString(), '2020-01-01 00:00:00']);
        $this->insert('customer_entity', [3, 'c@example.test', null, '2020-01-01 00:00:00']);

        $this->createTable('oauth_consumer', 'entity_id INT UNSIGNED NOT NULL PRIMARY KEY, secret VARCHAR(128) NOT NULL');
        $this->insert('oauth_consumer', [1, $this->encrypt(1, 'consumer secret')->toString()]);
        // A trailing line break: not the exact form a rewrite reproduces, so it counts as embedded.
        $this->insert('oauth_consumer', [2, $this->encrypt(1, 'with a line break')->toString() . "\n"]);

        $this->createTable('composite_secret', 'website_id SMALLINT UNSIGNED NOT NULL, code VARCHAR(32) NOT NULL, secret TEXT NOT NULL, PRIMARY KEY (website_id, code)');
        $this->insert('composite_secret', [0, 'b', $this->encrypt(1, 'w0 b')->toString()]);
        $this->insert('composite_secret', [0, 'a', $this->encrypt(1, 'w0 a')->toString()]);
        $this->insert('composite_secret', [1, 'a', $this->encrypt(1, 'w1 a')->toString()]);

        $this->createTable('keyless_secret', 'secret TEXT NOT NULL, label VARCHAR(64) NULL, UNIQUE KEY label (label)');
        $this->insert('keyless_secret', [$this->encrypt(1, 'no key')->toString(), 'nullable unique']);

        $this->createTable('token_store', 'token_hash CHAR(64) NOT NULL, note VARCHAR(64) NULL, secret TEXT NOT NULL,'
            . ' UNIQUE KEY a_note (note), UNIQUE KEY b_hash (token_hash)');
        $this->insert('token_store', [hash('sha256', 'a'), 'n', $this->encrypt(1, 'unique key')->toString()]);

        $this->createTable('payment_info', 'entity_id INT UNSIGNED NOT NULL PRIMARY KEY, additional_information LONGTEXT NULL');
        $this->insert('payment_info', [1, json_encode(['method' => 'card', 'token' => $this->encrypt(1, 'card token')->toString()], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES)]);
        // A JSON encoder's default output escapes every slash, so no 40 characters in a row are plain base64.
        $this->insert('payment_info', [9, json_encode(['token' => '1:3:' . str_repeat('ab/', 20)], JSON_THROW_ON_ERROR)]);
        $this->insert('payment_info', [2, json_encode(['method' => 'cash'], JSON_THROW_ON_ERROR)]);

        $this->createTable('binary_secret', 'id INT UNSIGNED NOT NULL PRIMARY KEY, secret VARBINARY(255) NULL');
        $this->insert('binary_secret', [1, $this->encrypt(1, 'in varbinary')->toString()]);
        $this->insert('binary_secret', [2, "\xff\xfe\x00 bytes that are no text \x80\x81"]);

        $this->createTable('blob_secret', 'id INT UNSIGNED NOT NULL PRIMARY KEY, secret BLOB NULL');
        $this->insert('blob_secret', [1, $this->encrypt(1, 'in blob')->toString()]);
        $this->insert('blob_secret', [2, 'a:1:{s:5:"token";s:60:"' . $this->encrypt(1, 'serialised')->toString() . '";}']);

        // Too short for any ciphertext, though the value has the shape of one.
        $this->createTable('short_code', 'id INT UNSIGNED NOT NULL PRIMARY KEY, code VARCHAR(32) NOT NULL');
        $this->insert('short_code', [1, '1:3:' . str_repeat('A', 28)]);

        // Not one of the store's tables: no prefix.
        $this->database->exec('CREATE TABLE foreign_secret (id INT NOT NULL PRIMARY KEY, secret TEXT)');
        $this->database->exec(sprintf('INSERT INTO foreign_secret VALUES (1, \'%s\')', $this->encrypt(1, 'foreign')->toString()));

        // The tool's own journal holds old ciphertexts and is never a candidate.
        $this->adapters->schema->ensure();
        $this->database->exec(sprintf(
            'INSERT INTO `%s` (run_id, table_name, column_name, row_key, old_value, new_value, direction, created_at)'
            . ' VALUES (\'%s\', \'core_config_data\', \'value\', \'{"config_id":1}\', \'%s\', \'%s\', \'forward\', NOW())',
            $this->database->table('encryption_key_rotation_journal'),
            self::RUN,
            $this->encrypt(0, 'old')->toString(),
            $this->encrypt(1, 'new')->toString(),
        ));
        $this->database->exec(sprintf('CREATE VIEW `%s` AS SELECT secret FROM `%s`', $this->database->table('secret_view'), $this->database->table('oauth_consumer')));
    }

    /**
     * @return array<string, array{rowKey: list<string>, auto: list<string>, shapes: array<int, int>, embedded: int, incomplete: bool}>
     */
    private function candidates(ScanScope $scope): array
    {
        $found = [];
        foreach ($this->adapters->finder->candidates($scope) as $candidate) {
            $found[$candidate->column()->toString()] = [
                'rowKey' => $candidate->rowKeyColumns(),
                'auto' => $candidate->autoUpdatedColumns(),
                'shapes' => $candidate->shapeCounts(),
                'embedded' => $candidate->embeddedCount(),
                'incomplete' => $candidate->scanIncomplete(),
            ];
        }
        ksort($found);

        return $found;
    }

    private function createTable(string $table, string $definition): void
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (%s) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4', $this->database->table($table), $definition));
    }

    /**
     * @param list<int|string|null> $values
     */
    private function insert(string $table, array $values): void
    {
        $statement = $this->database->connection()->prepare(sprintf(
            'INSERT INTO `%s` VALUES (%s)',
            $this->database->table($table),
            implode(', ', array_fill(0, count($values), '?')),
        ));
        $statement->execute($values);
    }
}
