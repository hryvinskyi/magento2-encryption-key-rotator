<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\JournalEntry;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use PHPUnit\Framework\TestCase;

/**
 * What every implementation of {@see ReencryptionWriter}, {@see JournalReverter}, {@see JournalPurger}
 * and {@see JournalSchema} must do, so the in-memory double the use case tests run against and the real
 * database adapters behave alike.
 *
 * Each implementation gets one concrete subclass. A subclass for the in-memory double lives under
 * `tests/Contract/` and runs with the unit tests; a subclass for an adapter that needs a database, a file
 * tree or a server lives under `tests/Integration/Contract/`, so it runs in the integration suite and
 * never on a host without those.
 *
 * The fixture is one table, named by the subclass, with an integer primary key `id` and a text column
 * whose values the tests rewrite. Values are compared byte for byte: the contract never decrypts.
 */
abstract class ReencryptionJournalContractTestCase extends TestCase
{
    private const RUN = '0000000000000000000000000000000a';
    private const OTHER_RUN = '0000000000000000000000000000000b';

    private ColumnRef $column;

    abstract protected function writer(): ReencryptionWriter;

    abstract protected function reverter(): JournalReverter;

    abstract protected function purger(): JournalPurger;

    abstract protected function schema(): JournalSchema;

    /**
     * Creates the fixture table, empty, and returns its value column (table name without the prefix).
     */
    abstract protected function createSecretTable(): ColumnRef;

    abstract protected function insertSecret(int $id, string $value): void;

    /**
     * Changes a value as the store's application would: directly, outside the journal.
     */
    abstract protected function changeSecret(int $id, string $value): void;

    abstract protected function deleteSecret(int $id): void;

    /**
     * @return string|null the stored bytes, or null when the row is gone
     */
    abstract protected function secret(int $id): ?string;

    protected function setUp(): void
    {
        $this->column = $this->createSecretTable();
        $this->schema()->ensure();
    }

    public function testApplyWritesEveryValueThatStillHoldsItsOldBytes(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));

        $result = $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1), $this->forward(2)]);

        self::assertSame(2, $result->applied());
        self::assertTrue($result->isClean());
        self::assertSame($this->new(1)->toString(), $this->secret(1));
        self::assertSame($this->new(2)->toString(), $this->secret(2));
    }

    public function testAValueChangedSinceItWasReadIsLeftAloneAndReportedAsChanged(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));
        $changedByTheStore = $this->ciphertext(0, 'written by the store meanwhile')->toString();
        $this->changeSecret(2, $changedByTheStore);

        $result = $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1), $this->forward(2)]);

        self::assertSame(1, $result->applied());
        self::assertCount(1, $result->conflicts());
        $conflict = $result->conflicts()[0];
        self::assertSame(ConflictReason::Changed, $conflict->reason());
        self::assertTrue($conflict->column()->equals($this->column));
        self::assertSame('{"id":2}', $conflict->rowKey()->toJson());
        self::assertSame($changedByTheStore, $this->secret(2));
        self::assertSame($this->new(1)->toString(), $this->secret(1));
    }

    public function testTheComparisonIsByteForByte(): void
    {
        $this->insertSecret(1, strtoupper($this->old(1)));

        $result = $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame(strtoupper($this->old(1)), $this->secret(1));
    }

    public function testARowThatIsGoneIsReportedAsMissing(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->deleteSecret(1);

        $result = $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Missing, $result->conflicts()[0]->reason());
    }

    public function testEveryAppliedWriteIsJournaledAndAConflictIsNot(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));
        $this->changeSecret(2, $this->ciphertext(0, 'store')->toString());

        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1), $this->forward(2)]);

        $entries = $this->pending($this->runId());
        self::assertCount(1, $entries);
        $entry = $entries[0];
        self::assertTrue($entry->runId()->equals($this->runId()));
        self::assertTrue($entry->column()->equals($this->column));
        self::assertSame('{"id":1}', $entry->rowKey()->toJson());
        self::assertSame($this->old(1), $entry->oldRaw());
        self::assertSame($this->new(1)->toString(), $entry->newRaw());
        self::assertSame(Direction::Forward, $entry->direction());
    }

    public function testTheJournalOfOneRunIsNotAnothers(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));

        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);
        $this->writer()->apply(new RunId(self::OTHER_RUN), Direction::Forward, [$this->forward(2)]);

        self::assertSame(['{"id":1}'], $this->pendingRows($this->runId()));
        self::assertSame(['{"id":2}'], $this->pendingRows(new RunId(self::OTHER_RUN)));
    }

    public function testBackWritesAreJournaledButNeverPending(): void
    {
        $this->insertSecret(1, $this->new(1)->toString());

        $result = $this->writer()->apply($this->runId(), Direction::Back, [$this->reencryption(1, $this->new(1)->toString(), $this->ciphertext(0, 'back 1'))]);

        self::assertSame(1, $result->applied());
        self::assertSame([], $this->pending($this->runId()));
        self::assertSame(1, $this->purger()->purge($this->runId()));
    }

    public function testPendingYieldsEveryForwardEntryOnceOldestFirst(): void
    {
        $writes = [];
        for ($id = 1; $id <= 5; $id++) {
            $this->insertSecret($id, $this->old($id));
            $writes[] = $this->forward($id);
        }
        $this->writer()->apply($this->runId(), Direction::Forward, array_slice($writes, 0, 2));
        $this->writer()->apply($this->runId(), Direction::Forward, array_slice($writes, 2));

        $entries = $this->pending($this->runId());

        self::assertSame(['{"id":1}', '{"id":2}', '{"id":3}', '{"id":4}', '{"id":5}'], array_map(static fn(JournalEntry $e): string => $e->rowKey()->toJson(), $entries));
        $ids = array_map(static fn(JournalEntry $e): int => $e->entryId(), $entries);
        $sorted = $ids;
        sort($sorted);
        self::assertSame($sorted, $ids);
        self::assertCount(5, array_unique($ids));
    }

    public function testRevertPutsTheOldBytesBackAndSettlesTheEntries(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1), $this->forward(2)]);

        $result = $this->reverter()->revert($this->pending($this->runId()));

        self::assertSame(2, $result->applied());
        self::assertTrue($result->isClean());
        self::assertSame($this->old(1), $this->secret(1));
        self::assertSame($this->old(2), $this->secret(2));
        self::assertSame([], $this->pending($this->runId()));
    }

    public function testRevertingAgainChangesNothing(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);
        $entries = $this->pending($this->runId());
        $this->reverter()->revert($entries);

        $again = $this->reverter()->revert($entries);

        self::assertSame(0, $again->applied());
        self::assertSame($this->old(1), $this->secret(1));
        self::assertSame([], $this->pending($this->runId()));
    }

    public function testARevertWhoseRowChangedIsAConflictAndTheEntryStaysPending(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);
        $rewritten = $this->ciphertext(1, 'rewritten by the store under the new key')->toString();
        $this->changeSecret(1, $rewritten);

        $result = $this->reverter()->revert($this->pending($this->runId()));

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame($rewritten, $this->secret(1));
        self::assertCount(1, $this->pending($this->runId()));
    }

    public function testSupersedeWritesTheBackValueJournalsItAndSettlesTheForwardEntry(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);
        $rewritten = $this->ciphertext(1, 'rewritten by the store under the new key')->toString();
        $this->changeSecret(1, $rewritten);
        $entry = $this->pending($this->runId())[0];
        $back = $this->ciphertext(0, 'the same plaintext under the old key');

        $result = $this->reverter()->supersede($entry, $this->reencryption(1, $rewritten, $back));

        self::assertSame(1, $result->applied());
        self::assertTrue($result->isClean());
        self::assertSame($back->toString(), $this->secret(1));
        self::assertSame([], $this->pending($this->runId()));
        self::assertSame(2, $this->purger()->purge($this->runId()), 'The forward entry and the journaled back write.');
    }

    public function testASupersedeWhoseCompareAndSwapMissesChangesNothing(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);
        $entry = $this->pending($this->runId())[0];
        $current = $this->ciphertext(1, 'what the store wrote last')->toString();
        $this->changeSecret(1, $current);

        $result = $this->reverter()->supersede($entry, $this->reencryption(1, $this->ciphertext(1, 'an earlier read')->toString(), $this->ciphertext(0, 'back')));

        self::assertSame(0, $result->applied());
        self::assertSame(ConflictReason::Changed, $result->conflicts()[0]->reason());
        self::assertSame($current, $this->secret(1));
        self::assertCount(1, $this->pending($this->runId()));
        self::assertSame(1, $this->purger()->purge($this->runId()), 'Only the forward entry.');
    }

    public function testPurgeDeletesTheRunsJournalAndOnlyIt(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->insertSecret(2, $this->old(2));
        $this->insertSecret(3, $this->old(3));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1), $this->forward(2)]);
        $this->writer()->apply(new RunId(self::OTHER_RUN), Direction::Forward, [$this->forward(3)]);

        self::assertSame(2, $this->purger()->purge($this->runId()));

        self::assertSame(['{"id":3}'], $this->pendingRows(new RunId(self::OTHER_RUN)));
        self::assertSame(0, $this->purger()->purge($this->runId()));
    }

    public function testEnsuringTheSchemaAgainKeepsTheJournal(): void
    {
        $this->insertSecret(1, $this->old(1));
        $this->writer()->apply($this->runId(), Direction::Forward, [$this->forward(1)]);

        $this->schema()->ensure();

        self::assertCount(1, $this->pending($this->runId()));
    }

    /**
     * @return list<JournalEntry>
     */
    private function pending(RunId $runId): array
    {
        $entries = [];
        foreach ($this->reverter()->pending($runId) as $batch) {
            self::assertNotSame([], $batch, 'A pending batch is never empty.');
            foreach ($batch as $entry) {
                $entries[] = $entry;
            }
        }

        return $entries;
    }

    /**
     * @return list<string>
     */
    private function pendingRows(RunId $runId): array
    {
        return array_map(static fn(JournalEntry $entry): string => $entry->rowKey()->toJson(), $this->pending($runId));
    }

    private function forward(int $id): Reencryption
    {
        return $this->reencryption($id, $this->old($id), $this->new($id));
    }

    private function reencryption(int $id, string $oldRaw, Ciphertext $new): Reencryption
    {
        return new Reencryption($this->column, new RowKey(['id' => $id]), $oldRaw, $new);
    }

    private function old(int $id): string
    {
        return $this->ciphertext(0, 'old value ' . $id)->toString();
    }

    private function new(int $id): Ciphertext
    {
        return $this->ciphertext(1, 'new value ' . $id);
    }

    /**
     * A value with the shape of a stored ciphertext; the contract compares bytes and never decrypts.
     */
    private function ciphertext(int $keyIndex, string $seed): Ciphertext
    {
        return new Ciphertext($keyIndex, 3, base64_encode(str_pad($seed, 48, '.')));
    }

    private function runId(): RunId
    {
        return new RunId(self::RUN);
    }
}
