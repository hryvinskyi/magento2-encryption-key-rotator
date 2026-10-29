<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunNotFound;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

/**
 * What every implementation of {@see RunStore} must do, so the in-memory double the use case tests run
 * against and the store on disk behave alike.
 *
 * Each implementation gets one concrete subclass. A subclass for the in-memory double lives under
 * `tests/Contract/` and runs with the unit tests; a subclass for an adapter that needs a file tree, a
 * database or a server lives under `tests/Integration/Contract/`, so it runs in the integration suite.
 */
abstract class RunStoreContractTestCase extends TestCase
{
    private const FIRST = '00000000000000000000000000000001';
    private const SECOND = '00000000000000000000000000000002';
    private const BEFORE = '00000000000000aa';
    private const WITH_NEW_KEY = '00000000000000bb';

    /**
     * A store over an empty state directory.
     */
    abstract protected function createStore(): RunStore;

    /**
     * A second store over the same state directory as the given one, as another process would open it.
     */
    abstract protected function concurrentStore(RunStore $store): RunStore;

    public function testALockHeldByOneStoreRefusesAnother(): void
    {
        $store = $this->createStore();
        $other = $this->concurrentStore($store);
        $store->lock();

        try {
            $other->lock();
            self::fail('Two stores held the lock of one state directory.');
        } catch (RunLocked) {
            $this->addToAssertionCount(1);
        } finally {
            $store->unlock();
        }

        $other->lock();
        $other->unlock();
    }

    public function testUnlockingAStoreThatHoldsNoLockIsHarmless(): void
    {
        $store = $this->createStore();
        $other = $this->concurrentStore($store);
        $store->lock();

        $other->unlock();

        try {
            $this->concurrentStore($store)->lock();
            self::fail('Unlocking another store released the lock.');
        } catch (RunLocked) {
            $this->addToAssertionCount(1);
        } finally {
            $store->unlock();
        }
    }

    public function testASavedRunIsReadBackAsItWasSaved(): void
    {
        $store = $this->createStore();
        $run = $this->reencryptedRun(self::FIRST);

        $store->save($run);

        self::assertSame($run->snapshot(), $store->get(new RunId(self::FIRST))->snapshot());
        self::assertSame($run->snapshot(), $this->concurrentStore($store)->get(new RunId(self::FIRST))->snapshot());
    }

    public function testSavingAgainReplacesWhatWasSaved(): void
    {
        $store = $this->createStore();
        $run = $this->startedRun(self::FIRST);
        $store->save($run);

        $run->keyPending(3, self::WITH_NEW_KEY, $this->moment(1));
        $store->save($run);

        $read = $store->get(new RunId(self::FIRST));
        self::assertSame(RunState::KeyPending, $read->state());
        self::assertSame(self::WITH_NEW_KEY, $read->intendedRingFingerprint());
    }

    public function testAnUnknownRunIsNotFound(): void
    {
        $this->expectException(RunNotFound::class);

        $this->createStore()->get(new RunId(self::FIRST));
    }

    public function testTheActiveRunIsTheUnfinishedOne(): void
    {
        $store = $this->createStore();
        self::assertNull($store->active());
        self::assertNull($store->latest());

        $rolledBack = $this->startedRun(self::FIRST);
        $rolledBack->rollingBack($this->moment(1));
        $rolledBack->rolledBack(self::BEFORE, $this->moment(2));
        $store->save($rolledBack);
        self::assertNull($store->active(), 'A rolled-back run is finished.');

        $store->save($this->reencryptedRun(self::SECOND, $this->moment(10)));

        self::assertSame(self::SECOND, $store->active()?->id()->toString());
    }

    public function testARetiredRunIsStillActive(): void
    {
        $store = $this->createStore();
        $run = $this->reencryptedRun(self::FIRST);
        $run->retirePending('00000000000000cc', [RunOverride::AcceptEmbedded], $this->moment(20));
        $run->retired('00000000000000cc', $this->moment(21));

        $store->save($run);

        self::assertSame(RunState::Retired, $store->active()?->state());
    }

    public function testTwoUnfinishedRunsAreAConflictNamingBoth(): void
    {
        $store = $this->createStore();
        $store->save($this->startedRun(self::FIRST));
        $store->save($this->startedRun(self::SECOND, $this->moment(5)));

        try {
            $store->active();
            self::fail('Two unfinished runs were accepted.');
        } catch (ConflictingRuns $conflict) {
            self::assertStringContainsString(self::FIRST, $conflict->getMessage());
            self::assertStringContainsString(self::SECOND, $conflict->getMessage());
        }
    }

    public function testTheLatestRunIsTheOneStartedLastFinishedOrNot(): void
    {
        $store = $this->createStore();
        $later = $this->startedRun(self::SECOND, $this->moment(100));
        $later->rollingBack($this->moment(101));
        $later->rolledBack(self::BEFORE, $this->moment(102));
        $store->save($later);
        $store->save($this->startedRun(self::FIRST, $this->moment(0)));

        self::assertSame(self::SECOND, $store->latest()?->id()->toString());
    }

    public function testKeptKeysAreReadBackPerRoleInIndexOrder(): void
    {
        $store = $this->createStore();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $added = KeyMaterial::base64Key();
        $retiredOne = KeyMaterial::rawKey();
        $retiredZero = KeyMaterial::base64Key();

        $store->keepKey($id, KeptKeyRole::Added, new KeySlot(3, $added));
        $store->keepKey($id, KeptKeyRole::Retired, new KeySlot(1, $retiredOne));
        $store->keepKey($id, KeptKeyRole::Retired, new KeySlot(0, $retiredZero));

        self::assertSame([[3, $added]], $this->entries($store->keptKeys($id, KeptKeyRole::Added)));
        self::assertSame([[0, $retiredZero], [1, $retiredOne]], $this->entries($store->keptKeys($id, KeptKeyRole::Retired)));
        self::assertSame([[3, $added]], $this->entries($this->concurrentStore($store)->keptKeys($id, KeptKeyRole::Added)));
        self::assertSame([], $store->keptKeys(new RunId(self::SECOND), KeptKeyRole::Added));
    }

    public function testKeepingTheSameKeyAgainIsANoOpAndAnotherOneIsRefused(): void
    {
        $store = $this->createStore();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $kept = KeyMaterial::base64Key();
        $store->keepKey($id, KeptKeyRole::Added, new KeySlot(3, $kept));

        $store->keepKey($id, KeptKeyRole::Added, new KeySlot(3, $kept));

        try {
            $store->keepKey($id, KeptKeyRole::Added, new KeySlot(3, KeyMaterial::base64Key()));
            self::fail('A kept key was replaced.');
        } catch (KeptMaterialConflict) {
            $this->addToAssertionCount(1);
        }
        self::assertSame([[3, $kept]], $this->entries($store->keptKeys($id, KeptKeyRole::Added)));
    }

    public function testPlaceholdersAreKeptAndNeverReplaced(): void
    {
        $store = $this->createStore();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $zero = KeyMaterial::placeholder();
        $one = KeyMaterial::placeholder();
        $store->keepPlaceholders($id, [new KeySlot(1, $one), new KeySlot(0, $zero)]);

        $store->keepPlaceholders($id, [new KeySlot(0, $zero), new KeySlot(1, $one)]);

        try {
            $store->keepPlaceholders($id, [new KeySlot(0, KeyMaterial::placeholder()), new KeySlot(1, $one)]);
            self::fail('Kept placeholders were replaced.');
        } catch (KeptMaterialConflict) {
            $this->addToAssertionCount(1);
        }
        self::assertSame([[0, $zero], [1, $one]], $this->entries($store->keptPlaceholders($id)));
        self::assertSame([[0, $zero], [1, $one]], $this->entries($this->concurrentStore($store)->keptPlaceholders($id)));
    }

    public function testARunWithoutPlaceholdersHasNone(): void
    {
        $store = $this->createStore();
        $store->save($this->startedRun(self::FIRST));

        self::assertSame([], $store->keptPlaceholders(new RunId(self::FIRST)));
    }

    public function testADiscardedRunLeavesNothingBehind(): void
    {
        $store = $this->createStore();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $store->backupDeploymentConfig($id);
        $store->keepKey($id, KeptKeyRole::Added, new KeySlot(3, KeyMaterial::base64Key()));
        $store->keepPlaceholders($id, [new KeySlot(0, KeyMaterial::placeholder())]);

        $store->discard($id);

        self::assertNull($store->active());
        self::assertNull($store->latest());
        self::assertSame([], $store->keptKeys($id, KeptKeyRole::Added));
        self::assertSame([], $store->keptPlaceholders($id));
        $this->expectException(RunNotFound::class);
        $store->get($id);
    }

    public function testDiscardingTwiceIsHarmless(): void
    {
        $store = $this->createStore();
        $id = new RunId(self::FIRST);
        $store->save($this->startedRun(self::FIRST));
        $store->discard($id);

        $store->discard($id);

        self::assertNull($store->latest());
    }

    public function testDiscardingOneRunKeepsTheOthers(): void
    {
        $store = $this->createStore();
        $finished = $this->startedRun(self::FIRST);
        $finished->rollingBack($this->moment(1));
        $finished->rolledBack(self::BEFORE, $this->moment(2));
        $store->save($finished);
        $store->save($this->startedRun(self::SECOND, $this->moment(3)));

        $store->discard(new RunId(self::FIRST));

        self::assertSame(self::SECOND, $store->get(new RunId(self::SECOND))->id()->toString());
    }

    private function startedRun(string $id, ?\DateTimeImmutable $at = null): RotationRun
    {
        return new RotationRun(new RunId($id), self::BEFORE, [0, 1], 2, $at ?? $this->moment(0));
    }

    private function reencryptedRun(string $id, ?\DateTimeImmutable $at = null): RotationRun
    {
        $start = $at ?? $this->moment(0);
        $run = $this->startedRun($id, $start);
        $run->keyPending(3, self::WITH_NEW_KEY, $start->add(new \DateInterval('PT1S')));
        $run->keyAdded(self::WITH_NEW_KEY, $start->add(new \DateInterval('PT2S')));
        $run->overridden(RunOverride::IgnoreWorkers, $start->add(new \DateInterval('PT3S')));
        $run->webConfirmed(true, $start->add(new \DateInterval('PT4S')));
        $run->reencrypted(new ScanSummary([1 => 0, 3 => 1178], 2, 1, 0, []), true, $start->add(new \DateInterval('PT5S')));

        return $run;
    }

    private function moment(int $seconds): \DateTimeImmutable
    {
        return (new \DateTimeImmutable('2026-10-29T10:00:00.000000+00:00'))->add(new \DateInterval(sprintf('PT%dS', $seconds)));
    }

    /**
     * @param list<KeySlot> $slots
     *
     * @return list<array{int, string}>
     */
    private function entries(array $slots): array
    {
        return array_map(static fn(KeySlot $slot): array => [$slot->index(), $slot->raw()], $slots);
    }
}
