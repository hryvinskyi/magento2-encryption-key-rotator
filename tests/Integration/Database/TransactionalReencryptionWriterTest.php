<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableWithoutRowKey;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\ScriptedRetryPause;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;

/**
 * The compare-and-swap writer on a real server: it applies and journals, keeps automatically updated
 * timestamps, leaves a value another client changed meanwhile alone, retries a lock wait timeout, and
 * rolls the whole batch back on any other failure.
 */
final class TransactionalReencryptionWriterTest extends DatabaseTestCase
{
    private ColumnRef $rpToken;

    protected function setUp(): void
    {
        parent::setUp();
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` (entity_id INT UNSIGNED NOT NULL PRIMARY KEY, rp_token VARCHAR(128) NULL,'
            . ' updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP) DEFAULT CHARSET=utf8mb4 COLLATE utf8mb4_general_ci',
            $this->database->table('customer_entity'),
        ));
        foreach ([1, 2, 3] as $id) {
            $this->database->connection()->prepare(sprintf('INSERT INTO `%s` VALUES (?, ?, ?)', $this->database->table('customer_entity')))
                ->execute([$id, $this->encrypt(0, 'token ' . $id)->toString(), '2020-01-01 00:00:00']);
        }
        $this->rpToken = new ColumnRef('customer_entity', 'rp_token');
        $this->adapters->schema->ensure();
    }

    public function testItAppliesJournalsAndKeepsTheRowsUpdateTime(): void
    {
        $forward = $this->forwardOf(0);

        $result = $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);

        self::assertSame(3, $result->applied());
        self::assertTrue($result->isClean());
        foreach ([1, 2, 3] as $id) {
            $stored = $this->stored('customer_entity', 'rp_token', 'entity_id = ?', $id);
            self::assertNotNull($stored);
            self::assertStringStartsWith('1:3:', $stored);
            self::assertSame('token ' . $id, $this->decrypt($stored));
            self::assertSame('2020-01-01 00:00:00', $this->stored('customer_entity', 'updated_at', 'entity_id = ?', $id), 'Re-encrypting does not make the row look changed.');
        }
        $journal = $this->database->select(sprintf(
            'SELECT run_id, table_name, column_name, row_key, old_value, new_value, direction, reverted_at FROM `%s` ORDER BY entry_id',
            $this->database->table('encryption_key_rotation_journal'),
        ));
        self::assertCount(3, $journal);
        self::assertSame([
            'run_id' => self::RUN,
            'table_name' => 'customer_entity',
            'column_name' => 'rp_token',
            'row_key' => '{"entity_id":1}',
            'old_value' => $forward[0]->oldRaw(),
            'new_value' => $forward[0]->new()->toString(),
            'direction' => 'forward',
            'reverted_at' => null,
        ], $journal[0]);
    }

    public function testTheStoresOwnUpdateStillMovesTheUpdateTime(): void
    {
        $this->database->exec(sprintf('UPDATE `%s` SET rp_token = NULL WHERE entity_id = 1', $this->database->table('customer_entity')));

        self::assertNotSame('2020-01-01 00:00:00', $this->stored('customer_entity', 'updated_at', 'entity_id = ?', 1));
    }

    public function testAValueAnotherClientChangedBetweenReadAndWriteIsAConflictAndItsJournalRowIsGone(): void
    {
        $forward = $this->forwardOf(0);
        $newer = $this->encrypt(0, 'reset again by the customer')->toString();
        $other = $this->database->connect();
        $other->prepare(sprintf('UPDATE `%s` SET rp_token = ? WHERE entity_id = 2', $this->database->table('customer_entity')))->execute([$newer]);

        $result = $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);

        self::assertSame(2, $result->applied());
        self::assertCount(1, $result->conflicts());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame('{"entity_id":2}', $result->conflicts()[0]->rowKey()->toJson());
        self::assertSame($newer, $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 2));
        self::assertSame(['{"entity_id":1}', '{"entity_id":3}'], array_column($this->database->select(sprintf(
            'SELECT row_key FROM `%s` ORDER BY entry_id',
            $this->database->table('encryption_key_rotation_journal'),
        )), 'row_key'));
    }

    public function testARowAnotherClientDeletedIsAMissingConflict(): void
    {
        $forward = $this->forwardOf(0);
        $this->database->connect()->exec(sprintf('DELETE FROM `%s` WHERE entity_id = 3', $this->database->table('customer_entity')));

        $result = $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);

        self::assertSame(2, $result->applied());
        self::assertSame(ConflictReason::Missing, $result->conflicts()[0]->reason());
        self::assertSame(2, $this->journalRows());
    }

    public function testTrailingSpacesMakeAnotherValueUnderAPadSpaceCollation(): void
    {
        $value = $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 1) ?? '';
        $this->database->connection()->prepare(sprintf('UPDATE `%s` SET rp_token = ? WHERE entity_id = 1', $this->database->table('customer_entity')))
            ->execute([$value . '  ']);

        $result = $this->adapters->writer->apply($this->runId(), Direction::Forward, [new Reencryption($this->rpToken, $this->rowKey(['entity_id' => 1]), $value, $this->encrypt(1, 'x'))]);

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame($value . '  ', $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 1));
    }

    public function testCompositeKeysAndBinaryColumnsAreWrittenByTheirExactBytes(): void
    {
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` (website_id SMALLINT NOT NULL, code VARCHAR(32) NOT NULL, secret BLOB NOT NULL, PRIMARY KEY (website_id, code))',
            $this->database->table('composite_secret'),
        ));
        foreach ([[0, 'a'], [0, 'b'], [1, 'a']] as [$website, $code]) {
            $this->database->connection()->prepare(sprintf('INSERT INTO `%s` VALUES (?, ?, ?)', $this->database->table('composite_secret')))
                ->execute([$website, $code, $this->encrypt(0, $website . $code)->toString()]);
        }
        $column = new ColumnRef('composite_secret', 'secret');
        $forward = [];
        foreach ($this->batches($column, 0, 2) as $batch) {
            foreach ($batch as $value) {
                $forward[] = $this->reencryption($column, $value, 1);
            }
        }

        $result = $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);

        self::assertSame(3, $result->applied());
        self::assertSame('0b', $this->decrypt($this->stored('composite_secret', 'secret', 'website_id = ? AND code = ?', 0, 'b') ?? ''));
        self::assertSame([], $this->batches($column, 0, 2));
    }

    public function testALockWaitTimeoutIsRetriedAndThenSucceeds(): void
    {
        $blocker = $this->database->connect();
        $blocker->beginTransaction();
        $blocker->query(sprintf('SELECT * FROM `%s` WHERE entity_id = 2 FOR UPDATE', $this->database->table('customer_entity')));
        $pause = new ScriptedRetryPause(static function () use ($blocker): void {
            if ($blocker->inTransaction()) {
                $blocker->commit();
            }
        });
        $adapters = new DatabaseAdapters($this->database->deploymentConfig('SET SESSION innodb_lock_wait_timeout = 1'), new RecordingProgress(), pause: $pause);

        $result = $adapters->writer->apply($this->runId(), Direction::Forward, $this->forwardOf(0));

        self::assertSame(3, $result->applied());
        self::assertSame([1], $pause->attempts());
        self::assertSame(3, $this->journalRows(), 'The aborted attempt left no journal row behind.');
    }

    public function testALockThatIsNeverReleasedFailsAfterThreeRetriesAndWritesNothing(): void
    {
        $forward = $this->forwardOf(0);
        $blocker = $this->database->connect();
        $blocker->beginTransaction();
        $blocker->query(sprintf('SELECT * FROM `%s` WHERE entity_id = 3 FOR UPDATE', $this->database->table('customer_entity')));
        $pause = new ScriptedRetryPause();
        $adapters = new DatabaseAdapters($this->database->deploymentConfig('SET SESSION innodb_lock_wait_timeout = 1'), new RecordingProgress(), pause: $pause);

        try {
            $adapters->writer->apply($this->runId(), Direction::Forward, $forward);
            self::fail('A lock that is never released fails the write.');
        } catch (\PDOException $exception) {
            self::assertSame(1205, $exception->errorInfo[1] ?? null);
        } finally {
            $blocker->rollBack();
        }

        self::assertSame([1, 2, 3], $pause->attempts());
        self::assertSame($forward[0]->oldRaw(), $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 1));
        self::assertSame(0, $this->journalRows());
    }

    public function testAnyOtherFailureRollsTheWholeBatchBack(): void
    {
        $forward = $this->forwardOf(0);
        $this->database->exec(sprintf('CREATE TABLE `%s` (secret TEXT NULL)', $this->database->table('keyless_secret')));
        $forward[] = new Reencryption(new ColumnRef('keyless_secret', 'secret'), $this->rowKey(['id' => 1]), 'old', $this->encrypt(1, 'x'));

        try {
            $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);
            self::fail('A row of a table without a row key is never written.');
        } catch (TableWithoutRowKey $exception) {
            self::assertStringContainsString('keyless_secret', $exception->getMessage());
        }

        self::assertSame($forward[0]->oldRaw(), $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 1));
        self::assertSame(0, $this->journalRows());
    }

    /**
     * Re-encryptions of every customer token under the index, onto index 1.
     *
     * @return list<Reencryption>
     */
    private function forwardOf(int $index): array
    {
        $forward = [];
        foreach ($this->batches($this->rpToken, $index, 500) as $batch) {
            foreach ($batch as $value) {
                $forward[] = $this->reencryption($this->rpToken, $value, 1);
            }
        }

        return $forward;
    }
}
