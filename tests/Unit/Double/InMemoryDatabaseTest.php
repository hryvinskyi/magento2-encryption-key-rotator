<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\CallLog;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use PHPUnit\Framework\TestCase;

/**
 * The behaviour of the in-memory database that the shared contract does not cover: discovery, paging and
 * the hooks use case tests drive it with.
 */
final class InMemoryDatabaseTest extends TestCase
{
    private InMemoryDatabase $database;

    protected function setUp(): void
    {
        $this->database = new InMemoryDatabase();
        $this->database->createTable('core_config_data', ['config_id'], ['path', 'value']);
        $this->database->createTable('customer_entity', ['entity_id'], ['rp_token'], ['updated_at']);
        $this->database->createTable('quote_payment', ['payment_id'], ['additional_information']);
        $this->database->createTable('import_log', [], ['secret']);
    }

    public function testDiscoveryCountsCiphertextsPerIndexEmbeddedValuesAndRowKeys(): void
    {
        $this->database->insert('core_config_data', ['config_id' => 1, 'path' => 'a/b/c', 'value' => $this->ciphertext(0)]);
        $this->database->insert('core_config_data', ['config_id' => 2, 'path' => 'a/b/d', 'value' => $this->ciphertext(1)]);
        $this->database->insert('core_config_data', ['config_id' => 3, 'path' => 'a/b/e', 'value' => $this->ciphertext(1)]);
        $this->database->insert('core_config_data', ['config_id' => 4, 'path' => 'a/b/f', 'value' => 'plain']);
        $this->database->insert('quote_payment', ['payment_id' => 9, 'additional_information' => '{"token":"' . $this->ciphertext(1) . '"}']);
        $this->database->insert('import_log', ['secret' => $this->ciphertext(1)]);
        $this->database->insert('customer_entity', ['entity_id' => 5, 'rp_token' => null, 'updated_at' => 0]);

        $candidates = $this->byColumn($this->database->candidates(new ScanScope([])));

        self::assertSame(['core_config_data.value', 'import_log.secret', 'quote_payment.additional_information'], array_keys($candidates));
        self::assertSame([0 => 1, 1 => 2], $candidates['core_config_data.value']->shapeCounts());
        self::assertSame(['config_id'], $candidates['core_config_data.value']->rowKeyColumns());
        self::assertSame(1, $candidates['quote_payment.additional_information']->embeddedCount());
        self::assertSame([], $candidates['quote_payment.additional_information']->shapeCounts());
        self::assertFalse($candidates['import_log.secret']->hasRowKey());
    }

    public function testDiscoveryReportsAutoUpdatedColumnsAndScansCutShort(): void
    {
        $this->database->insert('customer_entity', ['entity_id' => 5, 'rp_token' => $this->ciphertext(1), 'updated_at' => 0]);
        $this->database->cutScanShort('quote_payment', 'additional_information');

        $candidates = $this->byColumn($this->database->candidates(new ScanScope([])));

        self::assertSame(['updated_at'], $candidates['customer_entity.rp_token']->autoUpdatedColumns());
        self::assertTrue($candidates['quote_payment.additional_information']->scanIncomplete());
    }

    public function testDiscoveryHonoursTheScope(): void
    {
        $this->database->insert('core_config_data', ['config_id' => 1, 'path' => 'a', 'value' => $this->ciphertext(1)]);
        $this->database->insert('customer_entity', ['entity_id' => 5, 'rp_token' => $this->ciphertext(1), 'updated_at' => 0]);

        $candidates = $this->byColumn($this->database->candidates(new ScanScope(['customer_*'])));

        self::assertSame(['core_config_data.value'], array_keys($candidates));
    }

    public function testBatchesFollowTheRowKeyAndYieldEveryMatchingRowOnce(): void
    {
        foreach ([5, 1, 4, 2, 3] as $id) {
            $this->database->insert('core_config_data', ['config_id' => $id, 'path' => 'p' . $id, 'value' => $this->ciphertext($id === 4 ? 0 : 1)]);
        }

        $batches = [];
        foreach ($this->database->batches(new ColumnRef('core_config_data', 'value'), 1, 2) as $batch) {
            $batches[] = array_map(static fn(StoredValue $value): string => $value->rowKey()->toJson(), $batch);
        }

        self::assertSame([['{"config_id":1}', '{"config_id":2}'], ['{"config_id":3}', '{"config_id":5}']], $batches);
    }

    public function testARowChangedBetweenBatchesIsNeitherSkippedTwiceNorRepeated(): void
    {
        foreach ([1, 2, 3] as $id) {
            $this->database->insert('core_config_data', ['config_id' => $id, 'path' => 'p' . $id, 'value' => $this->ciphertext(1)]);
        }
        $seen = [];
        foreach ($this->database->batches(new ColumnRef('core_config_data', 'value'), 1, 1) as $batch) {
            $seen[] = $batch[0]->rowKey()->toJson();
            $this->database->update('core_config_data', ['config_id' => 1], 'value', $this->ciphertext(1, 'rewritten'));
        }

        self::assertSame(['{"config_id":1}', '{"config_id":2}', '{"config_id":3}'], $seen);
    }

    public function testTheWriteHookRunsBetweenTheReadAndTheCompareAndSwap(): void
    {
        $this->database->insert('core_config_data', ['config_id' => 1, 'path' => 'p', 'value' => $this->ciphertext(0)]);
        $this->database->ensure();
        $this->database->beforeEachWrite(static function (InMemoryDatabase $database, ColumnRef $column, RowKey $rowKey): void {
            $database->update($column->table(), ['config_id' => 1], $column->column(), 'changed by the store');
        });

        $result = $this->database->apply(new RunId(str_repeat('a', 32)), Direction::Forward, [
            new Reencryption(new ColumnRef('core_config_data', 'value'), new RowKey(['config_id' => 1]), $this->ciphertext(0), new Ciphertext(1, 3, base64_encode(str_repeat('n', 40)))),
        ]);

        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame('changed by the store', $this->database->value('core_config_data', ['config_id' => 1], 'value'));
        self::assertSame([], $this->database->journalEntries());
    }

    public function testTheStoresOwnWritesBumpAutoUpdatedColumnsAndTheToolsDoNot(): void
    {
        $this->database->insert('customer_entity', ['entity_id' => 5, 'rp_token' => $this->ciphertext(0), 'updated_at' => 100]);
        $this->database->ensure();

        $this->database->apply(new RunId(str_repeat('a', 32)), Direction::Forward, [
            new Reencryption(new ColumnRef('customer_entity', 'rp_token'), new RowKey(['entity_id' => 5]), $this->ciphertext(0), new Ciphertext(1, 3, base64_encode(str_repeat('n', 40)))),
        ]);
        self::assertSame(100, $this->database->value('customer_entity', ['entity_id' => 5], 'updated_at'));

        $this->database->update('customer_entity', ['entity_id' => 5], 'rp_token', 'x');
        self::assertSame(101, $this->database->value('customer_entity', ['entity_id' => 5], 'updated_at'));
    }

    public function testWritingBeforeTheJournalExistsIsATestBug(): void
    {
        $this->expectException(\LogicException::class);

        $this->database->apply(new RunId(str_repeat('a', 32)), Direction::Forward, []);
    }

    public function testPurgingTheLastEntriesDropsTheJournal(): void
    {
        $this->database->insert('core_config_data', ['config_id' => 1, 'path' => 'p', 'value' => $this->ciphertext(0)]);
        $this->database->ensure();
        $run = new RunId(str_repeat('a', 32));
        $this->database->apply($run, Direction::Forward, [
            new Reencryption(new ColumnRef('core_config_data', 'value'), new RowKey(['config_id' => 1]), $this->ciphertext(0), new Ciphertext(1, 3, base64_encode(str_repeat('n', 40)))),
        ]);

        self::assertSame(1, $this->database->purge($run));
        self::assertFalse($this->database->journalExists());
    }

    public function testCallsAreLogged(): void
    {
        $log = new CallLog();
        $database = new InMemoryDatabase(log: $log);
        $database->ensure();

        $database->apply(new RunId(str_repeat('a', 32)), Direction::Back, []);
        $database->revert([]);

        self::assertSame(['db.apply back 0', 'db.revert 0'], $log->events());
    }

    /**
     * @param list<ColumnCandidate> $candidates
     *
     * @return array<string, ColumnCandidate>
     */
    private function byColumn(array $candidates): array
    {
        $byColumn = [];
        foreach ($candidates as $candidate) {
            $byColumn[$candidate->column()->toString()] = $candidate;
        }
        ksort($byColumn);

        return $byColumn;
    }

    private function ciphertext(int $keyIndex, string $seed = 'value'): string
    {
        return (new Ciphertext($keyIndex, 3, base64_encode(str_pad($seed, 40, '.'))))->toString();
    }
}
