<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use PHPUnit\Framework\TestCase;

/**
 * A purge destroys a finished run's journal and kept keys only when nothing still needs them, and is gone
 * for good afterwards: purging again finds nothing.
 */
final class PurgeRotationTest extends TestCase
{
    private LifecycleWorld $life;

    protected function setUp(): void
    {
        $this->life = new LifecycleWorld();
        $this->life->world->seedDefault();
    }

    protected function tearDown(): void
    {
        $this->life->cleanUp();
    }

    public function testRefusesARunThatIsNeitherRetiredNorRolledBack(): void
    {
        $life = $this->life;
        $life->rotate();
        $journal = count($life->world->database->journalEntries($life->runId()));

        $result = $life->purge();

        self::assertSame(PurgeStatus::Refused, $result->status());
        self::assertSame([RefusalReason::StateDoesNotAllow], $this->reasons($result));
        self::assertSame(RunState::Reencrypted, $life->run()->state());
        self::assertCount($journal, $life->world->database->journalEntries($life->runId()), 'The journal is kept.');
        self::assertNotSame([], $life->world->runs->keptKeys($life->runId(), KeptKeyRole::Added));
    }

    public function testRemovesTheJournalAndTheRunDirectoryOfARetiredRun(): void
    {
        $life = $this->life;
        $life->rotateAndRetire();
        self::assertNotSame([], $life->world->database->journalEntries($life->runId()));

        $result = $life->purge();

        self::assertSame(PurgeStatus::Purged, $result->status(), $this->explain($result));
        self::assertSame(RunState::Purged, $result->state());
        self::assertSame([1, 2], $result->purgedIndices());
        self::assertSame(0, $result->stillReadable());
        self::assertFalse($result->acceptedLoss());
        self::assertGreaterThan(0, $result->journalEntriesDeleted());
        self::assertTrue($result->runDirectoryRemoved());
        self::assertSame([], $life->world->database->journalEntries($life->runId()));
        self::assertFalse($life->world->runs->holdsAnythingOf($life->runId()), 'The run record and every kept key are gone.');
        foreach ($life->world->seeded() as $location => $plaintext) {
            [$table, $id] = explode('#', $location);
            $raw = $table === 'core_config_data'
                ? $life->world->value($table, (int) $id, 'value', 'config_id')
                : $life->world->value($table, (int) $id, 'secret');
            self::assertSame($plaintext, $life->world->decryptNow($raw), $location);
        }
    }

    public function testRefusesWhileAValueOnARetiredIndexStillDecryptsWithAKeptKeyUnlessTheLossIsAccepted(): void
    {
        $life = $this->life;
        $life->rotateAndRetire();
        $life->world->seed('core_config_data', 9, 'value', 'straggler after the retirement', 1, 'config_id');

        $refused = $life->purge();

        self::assertSame(PurgeStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::ValuesStillReadable], $this->reasons($refused));
        self::assertSame(1, $refused->stillReadable());
        self::assertStringContainsString('1 in the database', $refused->refusals()[0]->message());
        self::assertTrue($life->world->runs->holdsAnythingOf($life->runId()), 'Nothing is deleted.');
        self::assertNotSame([], $life->world->database->journalEntries($life->runId()));

        $accepted = $life->purge(acceptLoss: true);

        self::assertSame(PurgeStatus::Purged, $accepted->status(), $this->explain($accepted));
        self::assertTrue($accepted->acceptedLoss());
        self::assertSame(1, $accepted->stillReadable());
        self::assertFalse($life->world->runs->holdsAnythingOf($life->runId()));
    }

    public function testRefusesWhileEmbeddedValuesMayStillNeedAKeptKey(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $world->database->createTable('sales_payment', ['entity_id'], ['additional_information']);
        $world->database->insert('sales_payment', [
            'entity_id' => 1,
            'additional_information' => json_encode(['token' => $world->encrypt('embedded secret', 1)], JSON_THROW_ON_ERROR),
        ]);
        $life->deployCommittedUnderNewKey();
        $life->retire($life->retireRequest(acceptEmbedded: true));

        $refused = $life->purge();

        self::assertSame([RefusalReason::ValuesStillReadable], $this->reasons($refused));
        self::assertSame(1, $refused->embedded());
        self::assertSame(PurgeStatus::Purged, $life->purge(acceptLoss: true)->status());
    }

    public function testAValueInATableWithoutARowKeyOnThePurgedIndexIsReportedApartFromEmbeddedValues(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $newKey = $life->newKey();
        self::assertSame(RollBackStatus::RolledBack, $life->rollBack()->status());
        $world->database->createTable('legacy_token', [], ['token']);
        $world->database->insert('legacy_token', ['token' => $world->encrypt('keyless secret', $newIndex, $newKey)]);

        $refused = $life->purge();

        self::assertSame([RefusalReason::ValuesStillReadable], $this->reasons($refused));
        self::assertSame(1, $refused->withoutRowKey());
        self::assertSame(0, $refused->embedded());
        self::assertSame(0, $refused->incompleteColumns());
        $message = $refused->refusals()[0]->message();
        self::assertStringContainsString('1 values on key indices ' . $newIndex . ' sit in columns whose table has no row key (legacy_token.token)', $message);
        self::assertStringNotContainsString('embedded', $message);

        $accepted = $life->purge(acceptLoss: true);

        self::assertSame(PurgeStatus::Purged, $accepted->status(), $this->explain($accepted));
        self::assertTrue($accepted->acceptedLoss());
        self::assertSame(1, $accepted->withoutRowKey());
    }

    public function testPurgesARolledBackRunOnceNothingIsLeftUnderTheNewKey(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $newKey = $life->newKey();
        self::assertSame(RollBackStatus::RolledBack, $life->rollBack()->status());
        $world->database->insert('oauth_consumer', ['entity_id' => 7, 'secret' => $world->encrypt('written with the new ring', $newIndex, $newKey), 'updated_at' => 0]);

        $refused = $life->purge();

        self::assertSame([RefusalReason::ValuesStillReadable], $this->reasons($refused));
        self::assertSame([$newIndex], $refused->purgedIndices());

        $world->database->delete('oauth_consumer', ['entity_id' => 7]);
        $purged = $life->purge();

        self::assertSame(PurgeStatus::Purged, $purged->status(), $this->explain($purged));
        self::assertFalse($world->runs->holdsAnythingOf($life->runId()));
    }

    public function testThePurgeGivesTheStoreUpAfterTheJournalAndBeforeTheRunDirectory(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotateAndRetire();
        $id = $life->runId()->toString();
        self::assertSame($id, $world->registry->claimed()['run_id'] ?? null, 'A retired run still holds the store.');

        self::assertSame(PurgeStatus::Purged, $life->purge()->status());

        self::assertNull($world->registry->claimed());
        $events = $world->log->events();
        $journal = array_search('db.purge ' . $id, $events, true);
        $release = array_search('registry.release ' . $id, $events, true);
        $discard = array_search('store.discard ' . $id, $events, true);
        self::assertIsInt($journal);
        self::assertIsInt($release);
        self::assertIsInt($discard);
        self::assertLessThan($release, $journal);
        self::assertLessThan($discard, $release);
    }

    public function testARolledBackRunHoldsTheStoreUntilItIsPurged(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        self::assertSame(RollBackStatus::RolledBack, $life->rollBack()->status());

        $refused = $world->rotate();

        self::assertSame(RotateStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::RunClaimedElsewhere], array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $refused->refusals()));
        self::assertStringContainsString('this state directory', $refused->refusals()[0]->message());

        self::assertSame(PurgeStatus::Purged, $life->purge()->status());
        self::assertSame(RotateStatus::Reencrypted, $world->rotate()->status());
    }

    public function testPurgingAgainFindsNothing(): void
    {
        $life = $this->life;
        $life->rotateAndRetire();
        $first = $life->purge();
        self::assertSame(PurgeStatus::Purged, $first->status());

        $again = $life->purge();
        self::assertSame(PurgeStatus::NothingToPurge, $again->status());
        $byId = $life->purge($life->runId());
        self::assertSame(PurgeStatus::NothingToPurge, $byId->status());
        self::assertSame($life->runId()->toString(), $byId->runId()?->toString());
    }

    public function testAPurgeInterruptedAfterTheJournalIsFinishedByRunningItAgain(): void
    {
        $life = $this->life;
        $life->rotateAndRetire();
        $life->world->database->purge($life->runId());

        $result = $life->purge();

        self::assertSame(PurgeStatus::Purged, $result->status(), $this->explain($result));
        self::assertSame(0, $result->journalEntriesDeleted());
        self::assertFalse($life->world->runs->holdsAnythingOf($life->runId()));
    }

    /**
     * @return list<RefusalReason>
     */
    private function reasons(PurgeResult $result): array
    {
        return array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $result->refusals());
    }

    private function explain(PurgeResult $result): string
    {
        return implode(' | ', array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals()));
    }
}
