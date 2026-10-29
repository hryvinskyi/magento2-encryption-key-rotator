<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;

/**
 * Undoing a run on a real server: reverting restores the old bytes and is idempotent, a reverted row
 * keeps its update time, a row the store rewrote is a conflict left pending, and superseding settles it
 * so a second rollback pass finds nothing pending.
 */
final class TransactionalJournalReverterTest extends DatabaseTestCase
{
    private ColumnRef $rpToken;

    /**
     * @var array<int, string> entity id => value before the run
     */
    private array $before = [];

    protected function setUp(): void
    {
        parent::setUp();
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` (entity_id INT UNSIGNED NOT NULL PRIMARY KEY, rp_token VARCHAR(128) NULL,'
            . ' updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP)',
            $this->database->table('customer_entity'),
        ));
        foreach ([1, 2, 3, 4, 5] as $id) {
            $this->before[$id] = $this->encrypt(0, 'token ' . $id)->toString();
            $this->database->connection()->prepare(sprintf('INSERT INTO `%s` VALUES (?, ?, ?)', $this->database->table('customer_entity')))
                ->execute([$id, $this->before[$id], '2020-01-01 00:00:00']);
        }
        $this->rpToken = new ColumnRef('customer_entity', 'rp_token');
        $this->adapters->schema->ensure();
        $forward = [];
        foreach ($this->batches($this->rpToken, 0, 500) as $batch) {
            foreach ($batch as $value) {
                $forward[] = $this->reencryption($this->rpToken, $value, 1);
            }
        }
        $this->adapters->writer->apply($this->runId(), Direction::Forward, $forward);
    }

    protected function adapters(): DatabaseAdapters
    {
        return new DatabaseAdapters($this->database->deploymentConfig(), journalBatchSize: 2);
    }

    public function testPendingEntriesComeInBatchesOldestFirst(): void
    {
        $batches = [];
        foreach ($this->adapters->reverter->pending($this->runId()) as $batch) {
            $batches[] = array_map(static fn(JournalEntry $entry): string => $entry->rowKey()->toJson(), $batch);
        }

        self::assertSame([['{"entity_id":1}', '{"entity_id":2}'], ['{"entity_id":3}', '{"entity_id":4}'], ['{"entity_id":5}']], $batches);
    }

    public function testRevertRestoresTheOldValuesAndIsIdempotent(): void
    {
        $entries = $this->pending();

        $first = $this->adapters->reverter->revert($entries);
        $second = $this->adapters->reverter->revert($entries);

        self::assertSame(5, $first->applied());
        self::assertTrue($first->isClean());
        self::assertSame(0, $second->applied());
        self::assertTrue($second->isClean(), 'An entry already reverted is skipped, not reported again.');
        foreach ($this->before as $id => $value) {
            self::assertSame($value, $this->stored('customer_entity', 'rp_token', 'entity_id = ?', $id));
            self::assertSame('2020-01-01 00:00:00', $this->stored('customer_entity', 'updated_at', 'entity_id = ?', $id));
        }
        self::assertSame([], $this->pending());
        self::assertSame(5, (int) $this->scalar(sprintf('SELECT COUNT(*) FROM `%s` WHERE reverted_at IS NOT NULL', $this->database->table('encryption_key_rotation_journal'))));
    }

    public function testARevertWhoseCompareAndSwapMissesIsReportedAndStaysPending(): void
    {
        $rewritten = $this->encrypt(1, 'reset by the customer after the run')->toString();
        $this->database->connect()->prepare(sprintf('UPDATE `%s` SET rp_token = ? WHERE entity_id = 4', $this->database->table('customer_entity')))->execute([$rewritten]);

        $result = $this->adapters->reverter->revert($this->pending());

        self::assertSame(4, $result->applied());
        self::assertCount(1, $result->conflicts());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame('{"entity_id":4}', $result->conflicts()[0]->rowKey()->toJson());
        self::assertSame($rewritten, $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 4));
        self::assertSame(['{"entity_id":4}'], array_map(static fn(JournalEntry $entry): string => $entry->rowKey()->toJson(), $this->pending()));
    }

    public function testSupersedeWritesTheBackValueJournalsItAndASecondPassSeesNothingPending(): void
    {
        $rewritten = $this->encrypt(1, 'reset by the customer after the run')->toString();
        $this->database->connect()->prepare(sprintf('UPDATE `%s` SET rp_token = ? WHERE entity_id = 4', $this->database->table('customer_entity')))->execute([$rewritten]);
        $this->adapters->reverter->revert($this->pending());
        $entry = $this->pending()[0];
        $back = new Reencryption($this->rpToken, $entry->rowKey(), $rewritten, $this->encrypt(0, 'reset by the customer after the run'));
        $updatedByTheStore = $this->stored('customer_entity', 'updated_at', 'entity_id = ?', 4);
        sleep(1);

        $result = $this->adapters->reverter->supersede($entry, $back);

        self::assertSame(1, $result->applied());
        self::assertTrue($result->isClean());
        self::assertSame($back->new()->toString(), $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 4));
        self::assertSame($updatedByTheStore, $this->stored('customer_entity', 'updated_at', 'entity_id = ?', 4), 'The back write keeps the time of the store\'s own change.');
        self::assertSame([], $this->pending(), 'A second rollback pass finds nothing to retry or report.');
        self::assertSame([[
            'row_key' => '{"entity_id":4}',
            'old_value' => $rewritten,
            'new_value' => $back->new()->toString(),
            'reverted_at' => null,
        ]], $this->database->select(sprintf(
            'SELECT row_key, old_value, new_value, reverted_at FROM `%s` WHERE direction = \'back\'',
            $this->database->table('encryption_key_rotation_journal'),
        )));
        self::assertNotNull($this->scalar(sprintf('SELECT reverted_at FROM `%s` WHERE entry_id = ?', $this->database->table('encryption_key_rotation_journal')), $entry->entryId()));

        $again = $this->adapters->reverter->supersede($entry, $back);

        self::assertSame(0, $again->applied());
        self::assertTrue($again->isClean());
    }

    public function testASupersedeWhoseCompareAndSwapMissesChangesNothing(): void
    {
        $entry = $this->pending()[3];
        $current = $this->encrypt(1, 'what the store wrote last')->toString();
        $this->database->connect()->prepare(sprintf('UPDATE `%s` SET rp_token = ? WHERE entity_id = 4', $this->database->table('customer_entity')))->execute([$current]);
        $stale = new Reencryption($this->rpToken, $entry->rowKey(), $this->encrypt(1, 'an earlier read')->toString(), $this->encrypt(0, 'back'));

        $result = $this->adapters->reverter->supersede($entry, $stale);

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame($current, $this->stored('customer_entity', 'rp_token', 'entity_id = ?', 4));
        self::assertCount(5, $this->pending());
        self::assertSame(5, $this->journalRows());
    }

    /**
     * @return list<JournalEntry>
     */
    private function pending(): array
    {
        $entries = [];
        foreach ($this->adapters->reverter->pending($this->runId()) as $batch) {
            foreach ($batch as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    private function scalar(string $sql, int|string ...$parameters): int|string|null
    {
        $value = $this->database->value($sql, array_values($parameters));

        return is_int($value) || is_string($value) ? $value : null;
    }
}
