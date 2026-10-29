<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Run\CorruptRunFile;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\RunSnapshotReader;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\IllegalRunTransition;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RetireRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\UnexpectedRingFingerprint;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectDateTimeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanSummaryFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RotationRunTest extends TestCase
{
    private const RUN_ID = '0123456789abcdef0123456789abcdef';
    private const BEFORE = '00000000000000aa';
    private const WITH_NEW_KEY = '00000000000000bb';
    private const WITH_PLACEHOLDERS = '00000000000000cc';
    private const RESTORED = '00000000000000dd';

    /**
     * Every state change the state machine allows, as source state => reachable states.
     */
    private const ALLOWED = [
        'started' => ['key_pending', 'rolling_back'],
        'key_pending' => ['key_pending', 'key_added', 'rolling_back'],
        'key_added' => ['web_confirmed', 'rolling_back'],
        'web_confirmed' => ['reencrypted', 'rolling_back'],
        'reencrypted' => ['reencrypted', 'retire_pending', 'rolling_back'],
        'retire_pending' => ['retire_pending', 'retired', 'rolling_back'],
        'retired' => ['purged', 'rolling_back'],
        'rolling_back' => ['rolling_back', 'rolled_back'],
        'rolled_back' => ['purged'],
        'purged' => [],
    ];

    private \DateTimeImmutable $now;

    protected function setUp(): void
    {
        $this->now = new \DateTimeImmutable('2026-10-29T10:00:00.000000+00:00');
    }

    public function testANewRunIsStartedAndRemembersTheRingBeforeIt(): void
    {
        $run = $this->started();

        self::assertSame(RunState::Started, $run->state());
        self::assertSame(self::BEFORE, $run->ringFingerprintBefore());
        self::assertSame(self::BEFORE, $run->ringFingerprint());
        self::assertSame([0, 1], $run->oldUsableIndices());
        self::assertSame(2, $run->activeIndexBefore());
        self::assertNull($run->newIndex());
        self::assertNull($run->intendedRingFingerprint());
        self::assertNull($run->lastRingWriteAt());
        self::assertTrue($run->isActive());
        self::assertFalse($run->isRollingBack());
        self::assertSame([['state' => RunState::Started, 'at' => $this->now]], $run->history());
    }

    /**
     * @return iterable<string, array{RunState, RunState}>
     */
    public static function allowedTransitions(): iterable
    {
        foreach (self::ALLOWED as $from => $targets) {
            foreach ($targets as $to) {
                yield $from . ' -> ' . $to => [RunState::from($from), RunState::from($to)];
            }
        }
    }

    #[DataProvider('allowedTransitions')]
    public function testEveryAllowedTransitionIsRecorded(RunState $from, RunState $to): void
    {
        $run = $this->runIn($from);
        $historyBefore = count($run->history());

        $this->attempt($run, $to);

        self::assertSame($to, $run->state());
        self::assertCount($historyBefore + 1, $run->history());
        self::assertSame($to, $run->history()[$historyBefore]['state']);
    }

    /**
     * @return iterable<string, array{RunState, RunState}>
     */
    public static function illegalTransitions(): iterable
    {
        foreach (RunState::cases() as $from) {
            foreach (RunState::cases() as $to) {
                if ($to === RunState::Started || in_array($to->value, self::ALLOWED[$from->value], true)) {
                    continue;
                }
                yield $from->value . ' -> ' . $to->value => [$from, $to];
            }
        }
    }

    #[DataProvider('illegalTransitions')]
    public function testEveryIllegalTransitionThrowsNamingBothStatesAndChangesNothing(RunState $from, RunState $to): void
    {
        $run = $this->runIn($from);
        $snapshot = $run->snapshot();

        try {
            $this->attempt($run, $to);
            self::fail(sprintf('"%s" -> "%s" was accepted.', $from->value, $to->value));
        } catch (IllegalRunTransition $illegal) {
            self::assertStringContainsString('"' . $from->value . '"', $illegal->getMessage());
            self::assertStringContainsString('"' . $to->value . '"', $illegal->getMessage());
            self::assertStringContainsString(self::RUN_ID, $illegal->getMessage());
        }
        self::assertSame($snapshot, $run->snapshot());
    }

    public function testKeyPendingAnnouncesTheNewIndexAndTheIntendedRing(): void
    {
        $run = $this->runIn(RunState::KeyPending);

        self::assertSame(3, $run->newIndex());
        self::assertSame(self::WITH_NEW_KEY, $run->intendedRingFingerprint());
        self::assertSame(self::BEFORE, $run->ringFingerprint());
        self::assertNull($run->lastRingWriteAt());
    }

    public function testKeyPendingIsReEntrantWithTheSameRing(): void
    {
        $run = $this->runIn(RunState::KeyPending);

        $run->keyPending(3, self::WITH_NEW_KEY, $this->later(5));

        self::assertSame(RunState::KeyPending, $run->state());
        self::assertSame(self::WITH_NEW_KEY, $run->intendedRingFingerprint());
        self::assertSame([RunState::Started, RunState::KeyPending, RunState::KeyPending], $this->states($run));
    }

    public function testAResumedKeyPendingThatNamesAnotherRingIsRefused(): void
    {
        $run = $this->runIn(RunState::KeyPending);

        $this->expectException(UnexpectedRingFingerprint::class);
        $this->expectExceptionMessage(self::WITH_NEW_KEY);

        $run->keyPending(3, self::RESTORED, $this->later(5));
    }

    public function testTheNewKeyTakesTheIndexAfterThePreviousActiveOne(): void
    {
        $run = $this->started();

        $this->expectException(InvalidRun::class);
        $this->expectExceptionMessage('the index after the active one, 3');

        $run->keyPending(4, self::WITH_NEW_KEY, $this->later(1));
    }

    public function testKeyAddedRecordsTheRingWriteAndItsMoment(): void
    {
        $run = $this->runIn(RunState::KeyPending);

        $run->keyAdded(self::WITH_NEW_KEY, $this->later(10));

        self::assertSame(RunState::KeyAdded, $run->state());
        self::assertSame(self::WITH_NEW_KEY, $run->ringFingerprint());
        self::assertNull($run->intendedRingFingerprint());
        self::assertEquals($this->later(10), $run->lastRingWriteAt());
    }

    public function testKeyAddedRefusesARingOtherThanTheAnnouncedOne(): void
    {
        $run = $this->runIn(RunState::KeyPending);

        try {
            $run->keyAdded(self::BEFORE, $this->later(10));
            self::fail('A ring other than the announced one was accepted.');
        } catch (UnexpectedRingFingerprint $mismatch) {
            self::assertStringContainsString(self::WITH_NEW_KEY, $mismatch->getMessage());
            self::assertStringContainsString(self::BEFORE, $mismatch->getMessage());
        }
        self::assertSame(RunState::KeyPending, $run->state());
        self::assertSame(self::WITH_NEW_KEY, $run->intendedRingFingerprint());
    }

    public function testASkippedWebProbeIsRecordedAsAnOverride(): void
    {
        $run = $this->runIn(RunState::KeyAdded);

        $run->webConfirmed(true, $this->later(20));

        self::assertTrue($run->probeSkipped());
        self::assertSame([RunOverride::SkipWebProbe], $this->overrideNames($run));
        self::assertSame(RunState::KeyAdded, $run->overrides()[0]['state']);
    }

    public function testAConfirmedWebProbeRecordsNoOverride(): void
    {
        $run = $this->runIn(RunState::WebConfirmed);

        self::assertFalse($run->probeSkipped());
        self::assertSame([], $run->overrides());
    }

    public function testReencryptedIsReEntrantAndKeepsTheLatestSummary(): void
    {
        $run = $this->runIn(RunState::Reencrypted);
        $second = new ScanSummary([3 => 12], 1, 0, 0, []);

        $run->reencrypted($second, false, $this->later(40));

        self::assertSame(RunState::Reencrypted, $run->state());
        self::assertSame($second, $run->lastSummary());
        self::assertFalse($run->configCacheCleaned());
        self::assertSame([RunState::Reencrypted, RunState::Reencrypted], array_slice($this->states($run), -2));
    }

    public function testRetirePendingAnnouncesThePlaceholderRing(): void
    {
        $run = $this->runIn(RunState::Reencrypted);

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));

        self::assertSame(RunState::RetirePending, $run->state());
        self::assertSame(self::WITH_PLACEHOLDERS, $run->intendedRingFingerprint());
        self::assertSame(self::WITH_NEW_KEY, $run->ringFingerprint());
    }

    public function testRetirePendingIsReEntrantWithTheSameRingAndSkipsTheChecksItAlreadyPassed(): void
    {
        $run = $this->runIn(RunState::RetirePending);

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(55));

        self::assertSame(RunState::RetirePending, $run->state());
        self::assertSame([RunState::RetirePending, RunState::RetirePending], array_slice($this->states($run), -2));
    }

    public function testAResumedRetirePendingThatNamesAnotherRingIsRefused(): void
    {
        $run = $this->runIn(RunState::RetirePending);

        $this->expectException(UnexpectedRingFingerprint::class);

        $run->retirePending(self::RESTORED, [], $this->later(55));
    }

    public function testRetirePendingRefusesWhileValuesRemainOnOldIndices(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([0 => 2, 1 => 3, 3 => 50], 0, 0, 0, []), true);

        try {
            $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));
            self::fail('Retiring was accepted with values left on old indices.');
        } catch (RetireRefused $refused) {
            self::assertStringContainsString('5 values still decrypt under the old key indices 0, 1, 2', $refused->getMessage());
        }
        self::assertSame(RunState::Reencrypted, $run->state());
        self::assertNull($run->intendedRingFingerprint());
        self::assertSame([], $run->overrides());
    }

    public function testRetirePendingCountsValuesLeftOnTheKeyThatWasActiveBeforeTheRun(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([2 => 4, 3 => 9], 0, 0, 0, []), true);

        $this->expectException(RetireRefused::class);
        $this->expectExceptionMessage('4 values still decrypt under the old key indices 0, 1, 2');

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));
    }

    public function testRetirePendingAllowsRemainingValuesWithTheOverrideAndRecordsIt(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([0 => 2], 0, 0, 0, []), true);

        $run->retirePending(self::WITH_PLACEHOLDERS, [RunOverride::AcceptRemaining], $this->later(50));

        self::assertSame(RunState::RetirePending, $run->state());
        self::assertSame([RunOverride::AcceptRemaining], $this->overrideNames($run));
        self::assertSame(RunState::Reencrypted, $run->overrides()[0]['state']);
    }

    public function testValuesInColumnsWithoutARowKeyOnAnOldIndexBlockTheRetirementWhateverIsAcknowledgedAsEmbedded(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, [1 => 2, 3 => 5]), true);

        try {
            $run->retirePending(self::WITH_PLACEHOLDERS, [RunOverride::AcceptEmbedded], $this->later(50));
            self::fail('Retiring was accepted with whole values left in a column without a row key.');
        } catch (RetireRefused $refused) {
            self::assertStringContainsString('2 values under the old key indices 0, 1, 2 sit in columns whose table has no row key', $refused->getMessage());
        }
        self::assertSame(RunState::Reencrypted, $run->state());
        self::assertSame([], $run->overrides());
    }

    public function testValuesInColumnsWithoutARowKeyOnlyOnTheNewIndexDoNotBlockTheRetirement(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, [3 => 5]), true);

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));

        self::assertSame(RunState::RetirePending, $run->state());
    }

    public function testValuesInColumnsWithoutARowKeyAreWaivedOnlyAsRemainingValues(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, [0 => 1]), true);

        $run->retirePending(self::WITH_PLACEHOLDERS, [RunOverride::AcceptRemaining], $this->later(50));

        self::assertSame([RunOverride::AcceptRemaining], $this->overrideNames($run));
    }

    public function testRetirePendingRefusesUnacknowledgedEmbeddedValuesAndIncompleteColumns(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 4, 1, []), true);

        $this->expectException(RetireRefused::class);
        $this->expectExceptionMessage('4 embedded values and 1 columns whose scan was cut short are not acknowledged');

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));
    }

    public function testRetirePendingAllowsEmbeddedValuesWithTheOverride(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 1, []), true);

        $run->retirePending(self::WITH_PLACEHOLDERS, [RunOverride::AcceptEmbedded], $this->later(50));

        self::assertSame([RunOverride::AcceptEmbedded], $this->overrideNames($run));
    }

    public function testRetirePendingRefusesWhenTheConfigCacheWasNotCleaned(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, []), false);

        $this->expectException(RetireRefused::class);
        $this->expectExceptionMessage('the configuration cache was not cleaned after the last re-encryption');

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));
    }

    public function testRetirePendingAllowsAManuallyCleanedCacheWithTheOverride(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, []), false);

        $run->retirePending(self::WITH_PLACEHOLDERS, [RunOverride::CacheCleanedManually], $this->later(50));

        self::assertSame(RunState::RetirePending, $run->state());
    }

    public function testRetirePendingNamesEveryReasonItRefusesFor(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([1 => 1], 0, 1, 0, []), false);

        try {
            $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));
            self::fail('Retiring was accepted.');
        } catch (RetireRefused $refused) {
            self::assertStringContainsString('1 values still decrypt', $refused->getMessage());
            self::assertStringContainsString('embedded', $refused->getMessage());
            self::assertStringContainsString('configuration cache', $refused->getMessage());
        }
    }

    public function testUndecryptableValuesDoNotBlockRetiring(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 7, 0, 0, []), true);

        $run->retirePending(self::WITH_PLACEHOLDERS, [], $this->later(50));

        self::assertSame(RunState::RetirePending, $run->state());
    }

    public function testRetiredRecordsTheRingWrite(): void
    {
        $run = $this->runIn(RunState::RetirePending);

        $run->retired(self::WITH_PLACEHOLDERS, $this->later(60));

        self::assertSame(RunState::Retired, $run->state());
        self::assertSame(self::WITH_PLACEHOLDERS, $run->ringFingerprint());
        self::assertNull($run->intendedRingFingerprint());
        self::assertEquals($this->later(60), $run->lastRingWriteAt());
        self::assertTrue($run->isActive());
    }

    public function testRetiredRefusesARingOtherThanTheAnnouncedOne(): void
    {
        $run = $this->runIn(RunState::RetirePending);

        $this->expectException(UnexpectedRingFingerprint::class);

        $run->retired(self::WITH_NEW_KEY, $this->later(60));
    }

    /**
     * @return iterable<string, array{RunState}>
     */
    public static function statesARollbackStartsFrom(): iterable
    {
        foreach (RunState::cases() as $state) {
            if ($state !== RunState::RolledBack && $state !== RunState::Purged && $state !== RunState::RollingBack) {
                yield $state->value => [$state];
            }
        }
    }

    #[DataProvider('statesARollbackStartsFrom')]
    public function testARollbackStartsFromEveryStateButRolledBackAndPurgedAndRemembersWhere(RunState $from): void
    {
        $run = $this->runIn($from);

        $run->rollingBack($this->later(100));

        self::assertSame(RunState::RollingBack, $run->state());
        self::assertTrue($run->isRollingBack());
        self::assertSame($from, $run->rolledBackFrom());
    }

    public function testRollingBackIsReEntrantAndKeepsTheStateItStartedFrom(): void
    {
        $run = $this->runIn(RunState::Retired);
        $run->rollingBack($this->later(100));

        $run->rollingBack($this->later(110));

        self::assertSame(RunState::RollingBack, $run->state());
        self::assertSame(RunState::Retired, $run->rolledBackFrom());
        self::assertSame([RunState::RollingBack, RunState::RollingBack], array_slice($this->states($run), -2));
    }

    public function testARollbackAnnouncesAndRecordsItsRingWrites(): void
    {
        $run = $this->runIn(RunState::Retired);
        $run->rollingBack($this->later(100));

        $run->rollbackRingPending(self::RESTORED, $this->later(101));
        self::assertSame(self::RESTORED, $run->intendedRingFingerprint());

        $run->rollbackRingWritten(self::RESTORED, $this->later(102));

        self::assertSame(RunState::RollingBack, $run->state());
        self::assertSame(self::RESTORED, $run->ringFingerprint());
        self::assertNull($run->intendedRingFingerprint());
        self::assertEquals($this->later(102), $run->lastRingWriteAt());
    }

    public function testARollbackRingWriteMustBeTheAnnouncedOne(): void
    {
        $run = $this->runIn(RunState::Retired);
        $run->rollingBack($this->later(100));
        $run->rollbackRingPending(self::RESTORED, $this->later(101));

        $this->expectException(UnexpectedRingFingerprint::class);

        $run->rollbackRingWritten(self::BEFORE, $this->later(102));
    }

    public function testARollbackRingWriteThatWasNotAnnouncedIsRefused(): void
    {
        $run = $this->runIn(RunState::Reencrypted);
        $run->rollingBack($this->later(100));

        $this->expectException(UnexpectedRingFingerprint::class);
        $this->expectExceptionMessage('announced no key ring write');

        $run->rollbackRingWritten(self::BEFORE, $this->later(102));
    }

    public function testOnlyARollingBackRunRecordsRollbackRingWrites(): void
    {
        $run = $this->runIn(RunState::Reencrypted);

        $this->expectException(IllegalRunTransition::class);
        $this->expectExceptionMessage('"reencrypted"');

        $run->rollbackRingPending(self::BEFORE, $this->later(101));
    }

    public function testRolledBackRequiresTheRingFromBeforeTheRun(): void
    {
        $run = $this->runIn(RunState::RollingBack);

        try {
            $run->rolledBack(self::WITH_NEW_KEY, $this->later(120));
            self::fail('A ring other than the one before the run was accepted.');
        } catch (UnexpectedRingFingerprint $mismatch) {
            self::assertStringContainsString(self::BEFORE, $mismatch->getMessage());
            self::assertStringContainsString(self::WITH_NEW_KEY, $mismatch->getMessage());
        }
        self::assertSame(RunState::RollingBack, $run->state());

        $run->rolledBack(self::BEFORE, $this->later(121));

        self::assertSame(RunState::RolledBack, $run->state());
        self::assertSame(self::BEFORE, $run->ringFingerprint());
        self::assertFalse($run->isActive());
    }

    public function testAPurgeThatAcceptedLossRecordsTheOverride(): void
    {
        $run = $this->runIn(RunState::Retired);

        $run->purged(true, $this->later(200));

        self::assertSame(RunState::Purged, $run->state());
        self::assertSame([RunOverride::AcceptLoss], $this->overrideNames($run));
        self::assertFalse($run->isActive());
    }

    public function testOverridesAreRecordedWithTheStateTheyWereGivenIn(): void
    {
        $run = $this->runIn(RunState::WebConfirmed);

        $run->overridden(RunOverride::IgnoreWorkers, $this->later(30));
        $run->overridden(RunOverride::AllowOtherUser, $this->later(31));

        self::assertSame([RunOverride::IgnoreWorkers, RunOverride::AllowOtherUser], $this->overrideNames($run));
        self::assertSame(RunState::WebConfirmed, $run->overrides()[1]['state']);
        self::assertEquals($this->later(31), $run->overrides()[1]['at']);
    }

    public function testAPurgedRunRecordsNoOverride(): void
    {
        $run = $this->runIn(RunState::Purged);

        $this->expectException(IllegalRunTransition::class);

        $run->overridden(RunOverride::IgnoreWorkers, $this->later(300));
    }

    public function testTheHistoryListsEveryRecordedStateInOrder(): void
    {
        $run = $this->runIn(RunState::Purged);

        self::assertSame(
            [
                RunState::Started, RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed,
                RunState::Reencrypted, RunState::RetirePending, RunState::Retired, RunState::Purged,
            ],
            $this->states($run),
        );
    }

    public function testTheSnapshotWritesStableKeys(): void
    {
        $snapshot = json_decode(json_encode($this->runIn(RunState::Retired)->snapshot(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR);
        self::assertIsArray($snapshot);

        self::assertSame(
            [
                'format', 'id', 'state', 'ring_fingerprint_before', 'old_usable_indices', 'active_index_before',
                'started_at', 'new_index', 'ring_fingerprint', 'intended_ring_fingerprint', 'last_ring_write_at',
                'probe_skipped', 'last_summary', 'config_cache_cleaned', 'rolled_back_from', 'overrides', 'history',
            ],
            array_keys($snapshot),
        );
        self::assertSame('retired', $snapshot['state']);
        self::assertSame('2026-10-29T10:00:00.000000+00:00', $snapshot['started_at']);
    }

    /**
     * @return iterable<string, array{RunState}>
     */
    public static function everyState(): iterable
    {
        foreach (RunState::cases() as $state) {
            yield $state->value => [$state];
        }
    }

    #[DataProvider('everyState')]
    public function testASnapshotReadBackRestoresTheSameRun(RunState $state): void
    {
        $run = $this->runIn($state);
        if ($state !== RunState::Purged) {
            $run->overridden(RunOverride::AllowOtherUser, $this->later(500));
        }
        $json = json_encode($run->snapshot(), JSON_THROW_ON_ERROR);

        $restored = $this->reader()->read(self::RUN_ID, json_decode($json, true, 512, JSON_THROW_ON_ERROR));

        self::assertSame($run->snapshot(), $restored->snapshot());
        self::assertSame($state, $restored->state());
        self::assertEquals($run->history(), $restored->history());
        self::assertEquals($run->lastSummary(), $restored->lastSummary());
    }

    public function testARestoredRunContinuesWhereItStopped(): void
    {
        $run = $this->runIn(RunState::KeyPending);
        $restored = $this->reader()->read(self::RUN_ID, json_decode(json_encode($run->snapshot(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));

        $restored->keyAdded(self::WITH_NEW_KEY, $this->later(10));

        self::assertSame(RunState::KeyAdded, $restored->state());
    }

    /**
     * @return iterable<string, array{\Closure(array<mixed>): array<mixed>, string}>
     */
    public static function corruptions(): iterable
    {
        yield 'a missing field' => [static function (array $s): array {
            unset($s['ring_fingerprint']);

            return $s;
        }, 'the field "ring_fingerprint" is missing'];
        yield 'an unknown state' => [static fn(array $s): array => ['state' => 'half_done'] + $s, 'unknown state "half_done"'];
        yield 'another run id' => [static fn(array $s): array => ['id' => 'ffffffffffffffffffffffffffffffff'] + $s, 'names another run'];
        yield 'a malformed moment' => [static fn(array $s): array => ['started_at' => 'yesterday'] + $s, '"started_at" is not a moment'];
        yield 'an impossible moment' => [static fn(array $s): array => ['started_at' => '2026-13-45T10:00:00.000000+00:00'] + $s, '"started_at" is not a valid moment'];
        yield 'a string where an integer belongs' => [static fn(array $s): array => ['active_index_before' => '2'] + $s, '"active_index_before" is not an integer'];
        yield 'a state without its facts' => [static fn(array $s): array => ['last_ring_write_at' => null] + $s, 'needs the moment of the last key ring write'];
        yield 'a history that ends elsewhere' => [static fn(array $s): array => ['history' => [['state' => 'started', 'at' => '2026-10-29T10:00:00.000000+00:00']]] + $s, 'last recorded state'];
        yield 'an empty history' => [static fn(array $s): array => ['history' => []] + $s, '"history" is empty'];
        yield 'an unknown format' => [static fn(array $s): array => ['format' => 99] + $s, 'format 99'];
        yield 'a malformed fingerprint' => [static fn(array $s): array => ['ring_fingerprint_before' => 'not-hex'] + $s, 'fingerprint'];
        yield 'an unknown override' => [static fn(array $s): array => ['overrides' => [['override' => 'trust_me', 'state' => 'started', 'at' => '2026-10-29T10:00:00.000000+00:00']]] + $s, 'unknown override "trust_me"'];
        yield 'a negative scan count' => [static fn(array $s): array => ['last_summary' => ['verified' => [], 'undecryptable' => -1, 'embedded' => 0, 'incomplete_columns' => 0]] + $s, 'cannot be negative'];
    }

    /**
     * @param \Closure(array<mixed>): array<mixed> $corrupt
     */
    #[DataProvider('corruptions')]
    public function testACorruptSnapshotThrowsNamingTheRun(\Closure $corrupt, string $reason): void
    {
        $snapshot = $corrupt($this->runIn(RunState::KeyAdded)->snapshot());

        try {
            $this->reader()->read(self::RUN_ID, $snapshot);
            self::fail('A corrupt snapshot was read.');
        } catch (CorruptRunFile $corrupted) {
            self::assertStringContainsString(self::RUN_ID, $corrupted->getMessage());
            self::assertStringContainsString($reason, $corrupted->getMessage());
        }
    }

    public function testASnapshotWrittenBeforeValuesWithoutARowKeyWereCountedPerIndexReadsWithNone(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 1, [1 => 2]), true);
        $snapshot = $run->snapshot();
        self::assertNotNull($snapshot['last_summary']);
        unset($snapshot['last_summary']['without_row_key']);

        $restored = $this->reader()->read(self::RUN_ID, $snapshot);

        self::assertSame([], $restored->lastSummary()?->withoutRowKeyPerIndex());
        self::assertSame(1, $restored->lastSummary()->incompleteColumns());
    }

    public function testASnapshotKeepsTheValuesWithoutARowKeyPerIndex(): void
    {
        $run = $this->reencryptedWith(new ScanSummary([3 => 9], 0, 0, 0, [1 => 2]), true);

        $restored = $this->reader()->read(self::RUN_ID, json_decode(json_encode($run->snapshot(), JSON_THROW_ON_ERROR), true, 512, JSON_THROW_ON_ERROR));

        self::assertSame([1 => 2], $restored->lastSummary()?->withoutRowKeyPerIndex());
    }

    public function testASnapshotThatIsNoObjectIsCorrupt(): void
    {
        $this->expectException(CorruptRunFile::class);
        $this->expectExceptionMessage(self::RUN_ID);

        $this->reader()->read(self::RUN_ID, 'run');
    }

    public function testOldUsableIndicesMustLieBelowTheActiveIndex(): void
    {
        $this->expectException(InvalidRun::class);

        new RotationRun(new RunId(self::RUN_ID), self::BEFORE, [0, 2], 2, $this->now);
    }

    private function started(): RotationRun
    {
        return (new DirectRotationRunFactory())->start(new RunId(self::RUN_ID), self::BEFORE, [1, 0], 2, $this->now);
    }

    /**
     * A run driven through its behaviour to the state, along the forward path (and the rollback path
     * for the rollback states).
     */
    private function runIn(RunState $state): RotationRun
    {
        $run = $this->started();
        $path = match ($state) {
            RunState::RollingBack => [RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted, RunState::RollingBack],
            RunState::RolledBack => [RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted, RunState::RollingBack, RunState::RolledBack],
            default => array_slice(
                [RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted, RunState::RetirePending, RunState::Retired, RunState::Purged],
                0,
                $state === RunState::Started ? 0 : (int) array_search($state, [RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed, RunState::Reencrypted, RunState::RetirePending, RunState::Retired, RunState::Purged], true) + 1,
            ),
        };
        foreach ($path as $next) {
            $this->attempt($run, $next);
        }

        return $run;
    }

    private function reencryptedWith(ScanSummary $summary, bool $cacheCleaned): RotationRun
    {
        $run = $this->runIn(RunState::WebConfirmed);
        $run->reencrypted($summary, $cacheCleaned, $this->later(40));

        return $run;
    }

    /**
     * Asks the run to record the state, with arguments that are valid for a run that may record it.
     */
    private function attempt(RotationRun $run, RunState $next): void
    {
        $at = $this->later(count($run->history()));
        match ($next) {
            RunState::Started => throw new \LogicException('No run records "started" again.'),
            RunState::KeyPending => $run->keyPending(3, self::WITH_NEW_KEY, $at),
            RunState::KeyAdded => $run->keyAdded(self::WITH_NEW_KEY, $at),
            RunState::WebConfirmed => $run->webConfirmed(false, $at),
            RunState::Reencrypted => $run->reencrypted(new ScanSummary([3 => 10], 0, 0, 0, []), true, $at),
            RunState::RetirePending => $run->retirePending(self::WITH_PLACEHOLDERS, [], $at),
            RunState::Retired => $run->retired(self::WITH_PLACEHOLDERS, $at),
            RunState::RollingBack => $run->rollingBack($at),
            RunState::RolledBack => $run->rolledBack(self::BEFORE, $at),
            RunState::Purged => $run->purged(false, $at),
        };
    }

    /**
     * @return list<RunState>
     */
    private function states(RotationRun $run): array
    {
        return array_map(static fn(array $entry): RunState => $entry['state'], $run->history());
    }

    /**
     * @return list<RunOverride>
     */
    private function overrideNames(RotationRun $run): array
    {
        return array_map(static fn(array $entry): RunOverride => $entry['override'], $run->overrides());
    }

    private function later(int $seconds): \DateTimeImmutable
    {
        return $this->now->add(new \DateInterval(sprintf('PT%dS', $seconds)));
    }

    private function reader(): RunSnapshotReader
    {
        return new RunSnapshotReader(new DirectRotationRunFactory(), new DirectRunIdFactory(), new DirectScanSummaryFactory(), new DirectDateTimeFactory());
    }
}
