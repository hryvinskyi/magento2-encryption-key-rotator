<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Purging deletes a run's journal in batches, keeps other runs' entries, and drops the journal table
 * once it is empty.
 */
final class BatchedJournalPurgerTest extends DatabaseTestCase
{
    private const OTHER_RUN = 'fedcba9876543210fedcba9876543210';

    public function testThePurgerEmptiesAndDropsTheJournal(): void
    {
        $this->journalForward($this->runId(), 1, 2500);
        $this->journalForward(new RunId(self::OTHER_RUN), 2501, 2502);

        self::assertSame(2500, $this->adapters->purger->purge($this->runId()));
        self::assertTrue($this->adapters->schema->exists(), 'Another run still has entries.');
        self::assertSame(2, $this->journalRows());

        self::assertSame(2, $this->adapters->purger->purge(new RunId(self::OTHER_RUN)));
        self::assertFalse($this->adapters->schema->exists());
        self::assertSame(0, $this->adapters->purger->purge($this->runId()), 'Purging again with no journal deletes nothing.');
    }

    public function testEnsuringTheSchemaRecreatesADroppedJournal(): void
    {
        $this->journalForward($this->runId(), 1, 1);
        $this->adapters->purger->purge($this->runId());

        $this->adapters->schema->ensure();
        $this->journalForward($this->runId(), 2, 2);

        self::assertSame(1, $this->journalRows());
    }

    /**
     * Journals forward writes of rows `from` to `to` of a table it creates when needed.
     */
    private function journalForward(RunId $runId, int $from, int $to): void
    {
        $table = $this->database->table('oauth_consumer');
        $this->database->exec(sprintf('CREATE TABLE IF NOT EXISTS `%s` (entity_id INT NOT NULL PRIMARY KEY, secret TEXT NOT NULL)', $table));
        $this->adapters->schema->ensure();
        $old = $this->encrypt(0, 'secret')->toString();
        $new = $this->encrypt(1, 'secret');
        $values = [];
        for ($id = $from; $id <= $to; $id++) {
            $values[] = sprintf('(%d, \'%s\')', $id, $old);
        }
        foreach (array_chunk($values, 500) as $chunk) {
            $this->database->exec(sprintf('INSERT INTO `%s` VALUES %s', $table, implode(', ', $chunk)));
        }
        $column = new ColumnRef('oauth_consumer', 'secret');
        $writes = [];
        for ($id = $from; $id <= $to; $id++) {
            $writes[] = new Reencryption($column, $this->rowKey(['entity_id' => $id]), $old, $new);
        }
        foreach (array_chunk($writes, 500) as $chunk) {
            self::assertSame(count($chunk), $this->adapters->writer->apply($runId, Direction::Forward, $chunk)->applied());
        }
    }
}
