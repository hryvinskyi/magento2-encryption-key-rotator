<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * A rotation appends a key, waits for the web tier to hold it, and moves every value under the previous
 * keys onto it; every safety check stops it before the write it guards.
 */
final class RotateKeyTest extends TestCase
{
    private RotationWorld $world;

    protected function setUp(): void
    {
        $this->world = (new RotationWorld())->seedDefault();
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
    }

    public function testARotationAppendsTheKeyAndMovesEveryOldValueOntoIt(): void
    {
        $world = $this->world;
        $originals = $this->storedValues();

        $result = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status(), $this->refusalText($result));
        self::assertSame(RunState::Reencrypted, $result->state());
        $run = $this->runOf($result);
        self::assertSame(RunState::Reencrypted, $run->state());

        $ring = $world->config->keyRing();
        self::assertCount(4, $ring->slots(), 'Exactly one slot is appended.');
        self::assertSame($world->ringBefore->export(), implode("\n", array_slice(explode("\n", $ring->export()), 0, 3)), 'No slot before it moved.');
        $kept = $world->runs->keptKeys($run->id(), KeptKeyRole::Added);
        self::assertCount(1, $kept);
        self::assertSame(3, $kept[0]->index());
        self::assertSame($kept[0]->raw(), $ring->slot(3)?->raw());
        self::assertSame($ring->fingerprint(), $run->ringFingerprint());
        self::assertSame($ring->fingerprint(), $result->ringFingerprint());

        foreach ($world->seeded() as $where => $plaintext) {
            [$table, $id] = explode('#', $where);
            $value = $world->value($table, (int) $id, $table === 'core_config_data' ? 'value' : 'secret', $table === 'core_config_data' ? 'config_id' : 'entity_id');
            self::assertStringStartsWith('3:3:', $value, $where);
            self::assertSame($plaintext, $world->decryptNow($value), $where);
        }
        self::assertSame('not encrypted', $world->value('oauth_consumer', 3, 'secret'));

        $journal = $world->database->journalEntries($run->id());
        self::assertCount(7, $journal);
        foreach ($journal as $entry) {
            self::assertSame(Direction::Forward, $entry->direction());
            self::assertSame($originals[$entry->column()->toString() . $entry->rowKey()->toJson()], $entry->oldRaw());
        }

        $env = $world->config->systemValues()[0];
        self::assertSame(3, $env->ciphertext()->keyIndex());
        self::assertSame('env secret', $world->decryptNow($env->ciphertext()->toString()));
        self::assertSame(['payment/gateway/api_secret'], $result->rewrittenSystemPaths());

        self::assertSame(1, $world->cache->calls());
        self::assertTrue($result->cacheClean()?->cleaned());
        self::assertTrue($run->configCacheCleaned());
        self::assertTrue($result->bearerTokensInvalidated());
        self::assertSame([1, 2], $result->sourceIndices());
        self::assertSame(3, $result->newIndex());
        self::assertSame(1, $world->runs->backupCount($run->id()));
        self::assertSame([1 => 1, 3 => 8], $run->lastSummary()?->verifiedPerIndex(), 'The committed value stays on its old index; it is only read.');
        self::assertSame(
            ['started', 'key_pending', 'key_added', 'web_confirmed', 'reencrypted'],
            array_map(static fn(array $entry): string => $entry['state']->value, $run->history()),
        );
        self::assertSame([$world->ringBefore->fingerprint(), $ring->fingerprint()], $world->probe->observed());
    }

    public function testTheOrderIsBaselineProbeKeyWriteProbeThenValues(): void
    {
        $world = $this->world;

        $world->rotate();

        $ring = $world->config->keyRing();
        $log = $world->log;
        $baseline = $log->firstPosition('probe.observe ' . $world->ringBefore->fingerprint());
        $pending = $log->firstPosition('store.save key_pending');
        $write = $log->firstPosition('config.write ' . $ring->fingerprint());
        $added = $log->firstPosition('store.save key_added');
        $probe = $log->firstPosition('probe.observe ' . $ring->fingerprint());
        $values = $log->firstPosition('db.apply forward');
        $cache = $log->firstPosition('cache.clean');
        $done = $log->firstPosition('store.save reencrypted');
        $positions = [$baseline, $pending, $write, $added, $probe, $values, $cache, $done];
        self::assertNotContains(null, $positions, implode("\n", $log->events()));
        $sorted = $positions;
        sort($sorted);
        self::assertSame($sorted, $positions, implode("\n", $log->events()));
    }

    public function testAKeyTheOperatorSuppliesIsTheOneAppended(): void
    {
        $raw = KeyMaterial::base64Key();

        $result = $this->world->rotate($this->world->request(rawKey: $raw));

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertSame($raw, $this->world->config->keyRing()->slot(3)?->raw());
    }

    public function testAKeyTheRingAlreadyHoldsOrThatIsNoKeyIsRejectedBeforeAnything(): void
    {
        foreach ([$this->world->key(2)->raw(), 'too-short'] as $raw) {
            $result = $this->world->rotate($this->world->request(rawKey: $raw));

            self::assertSame(RotateStatus::Refused, $result->status());
            self::assertSame([RefusalReason::KeyRejected], $this->reasons($result));
            self::assertStringNotContainsString($raw, $this->refusalText($result));
        }
        $this->assertNothingWritten();
    }

    public function testADryRunReportsThePlanAndWritesNothing(): void
    {
        $world = $this->world;
        $world->runs->concurrentHandle()->lock();
        $before = $this->storedValues();

        $result = $world->rotate($world->request(dryRun: true));

        self::assertSame(RotateStatus::DryRun, $result->status());
        self::assertSame([1, 2], $result->sourceIndices());
        self::assertSame(3, $result->newIndex());
        self::assertSame($world->ringBefore->fingerprint(), $result->ringFingerprint());
        self::assertSame([1 => 4, 2 => 5], $result->scan()?->summary()->verifiedPerIndex());
        self::assertSame([], $result->refusals());
        self::assertFalse($result->bearerTokensInvalidated());
        self::assertSame($before, $this->storedValues());
        $this->assertNothingWritten();
        self::assertSame([$world->ringBefore->fingerprint()], $world->probe->observed(), 'Asked once, for the current ring.');
        self::assertSame('matches', $result->probe()?->status()->value);
    }

    public function testADryRunListsAProbeThatDoesNotReachTheWebTier(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->differs());

        $result = $world->rotate($world->request(dryRun: true));

        self::assertSame(RotateStatus::DryRun, $result->status());
        self::assertSame([RefusalReason::BaselineProbeFailed], $this->reasons($result));
        self::assertSame('differs', $result->probe()?->status()->value);
        self::assertSame([1 => 4, 2 => 5], $result->scan()?->summary()->verifiedPerIndex(), 'The plan is still scanned.');
        $this->assertNothingWritten();
    }

    public function testADryRunWithTheProbeSkippedOrUnchosenAsksNobody(): void
    {
        $world = $this->world;
        $unchosen = new ProbeSettings(null, null, null, ProbeSettings::DEFAULT_DOCROOT, true, 30, false);

        $skipped = $world->rotate($world->request(dryRun: true, probeSettings: $world->probeSettings(skipped: true)));
        $none = $world->rotate($world->request(dryRun: true, probeSettings: $unchosen));

        self::assertSame([], $world->probe->observed());
        self::assertNull($skipped->probe());
        self::assertNull($none->probe());
        self::assertSame([], $skipped->refusals());
        self::assertSame([], $none->refusals());
    }

    public function testADryRunListsWhatWouldRefuseTheRotation(): void
    {
        $this->world->config->holdNonLiteralData();

        $result = $this->world->rotate($this->world->request(dryRun: true));

        self::assertSame(RotateStatus::DryRun, $result->status());
        self::assertSame([RefusalReason::DeploymentConfigNotLiteral], $this->reasons($result));
        $this->assertNothingWritten();
    }

    public function testABaselineProbeThatDoesNotMatchStopsBeforeAnyWrite(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->differs());

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::BaselineProbeFailed], $this->reasons($result));
        self::assertSame('differs', $result->probe()?->status()->value);
        self::assertNull($result->runId());
        $this->assertNothingWritten();
    }

    public function testASkippedProbeIsNotAskedAndIsRecorded(): void
    {
        $world = $this->world;

        $result = $world->rotate($world->request(probeSettings: $world->probeSettings(skipped: true)));

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertSame([], $world->probe->observed());
        $run = $this->runOf($result);
        self::assertTrue($run->probeSkipped());
        self::assertSame([RunOverride::SkipWebProbe], $this->overrides($run));
    }

    public function testRunningWorkersStopTheRotationBeforeAnyWrite(): void
    {
        $world = $this->world;
        $world->workers->start('bin/magento cron:run', $world->clock->now()->modify('-60 seconds'));
        $world->workers->start('bin/magento queue:consumers:start async', null);

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::WorkersRunning], $this->reasons($result));
        self::assertSame(
            ['bin/magento cron:run', 'bin/magento queue:consumers:start async'],
            array_map(static fn(RunningProcess $process): string => $process->description(), $result->workers()),
        );
        $this->assertNothingWritten();
    }

    public function testIgnoringWorkersLetsTheRotationPassAndIsRecorded(): void
    {
        $world = $this->world;
        $world->workers->start('bin/magento cron:run', $world->clock->now()->modify('-60 seconds'));

        $result = $world->rotate($world->request(ignoreWorkers: true));

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertCount(1, $result->workers());
        $overrides = $this->runOf($result)->overrides();
        self::assertSame([RunOverride::IgnoreWorkers, RunOverride::IgnoreWorkers], array_column($overrides, 'override'));
        self::assertSame([RunState::Started, RunState::WebConfirmed], array_column($overrides, 'state'), 'Waived before the run started and again before the values moved.');
    }

    public function testAWorkerStartedBeforeTheKeyWriteBlocksTheReencryption(): void
    {
        $world = $this->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::KeyPending) {
                $world->workers->start('bin/magento indexer:reindex', $world->clock->now());
                $world->clock->sleep(1);
                $world->runs->afterSave(null);
            }
        });
        $before = $this->storedValues();

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::WorkersRunning], $this->reasons($result));
        self::assertSame(RunState::WebConfirmed, $result->state());
        self::assertSame($before, $this->storedValues());
        self::assertSame([], $world->log->eventsStartingWith('db.apply'));

        $passed = $world->rotate($world->request(ignoreWorkers: true));

        self::assertSame(RotateStatus::Reencrypted, $passed->status());
        self::assertSame([RunOverride::IgnoreWorkers], $this->overrides($this->runOf($passed)));
    }

    public function testAProcessUserOtherThanTheOwnerIsRefused(): void
    {
        $this->world->cleanUp();
        $this->world = (new RotationWorld(runtimeUid: 0))->seedDefault();

        $result = $this->world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::OtherUser], $this->reasons($result));
        $this->assertNothingWritten();
    }

    public function testAllowingAnotherUserLetsTheRotationPassAndIsRecorded(): void
    {
        $this->world->cleanUp();
        $this->world = (new RotationWorld(runtimeUid: 0))->seedDefault();

        $result = $this->world->rotate($this->world->request(allowOtherUser: true));

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertContains(RunOverride::AllowOtherUser, $this->overrides($this->runOf($result)));
    }

    public function testADeploymentConfigWithMoreThanLiteralDataIsRefusedBeforeAnyWrite(): void
    {
        $this->world->config->holdNonLiteralData();

        $result = $this->world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::DeploymentConfigNotLiteral], $this->reasons($result));
        $this->assertNothingWritten();
    }

    public function testADeploymentConfigTheProcessCannotWriteIsRefusedBeforeAnyWrite(): void
    {
        $this->world->config->makeUnwritable();

        $result = $this->world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::DeploymentConfigNotWritable], $this->reasons($result));
        self::assertSame([], $this->world->probe->observed(), 'Refused before the baseline probe.');
        $this->assertNothingWritten();
    }

    public function testARotationClaimsTheStoreForItsRunAndTheStateDirectoryItIsKeptIn(): void
    {
        $result = $this->world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status(), $this->refusalText($result));
        self::assertSame(
            ['run_id' => $this->runOf($result)->id()->toString(), 'state_directory' => $this->world->stateDirectory],
            $this->world->registry->claimed(),
        );
        $events = $this->world->log->events();
        self::assertLessThan(
            array_search('store.save started', $events, true),
            array_search('registry.claim ' . $this->runOf($result)->id()->toString(), $events, true),
            'The store is claimed before the run writes anything.',
        );
    }

    public function testARunOfAnotherStateDirectoryHoldingTheStoreRefusesANewRotationBeforeAnyWrite(): void
    {
        $other = new RunId(str_repeat('f', 32));
        $this->world->registry->claim($other, '/srv/elsewhere/rotation');

        $result = $this->world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RunClaimedElsewhere], $this->reasons($result));
        self::assertStringContainsString($other->toString(), $result->refusals()[0]->message());
        self::assertStringContainsString('/srv/elsewhere/rotation', $result->refusals()[0]->message());
        self::assertSame($other->toString(), $this->world->registry->claimed()['run_id'] ?? null);
        $this->assertNothingWritten();
    }

    public function testADryRunListsAnotherRunHoldingTheStore(): void
    {
        $this->world->registry->claim(new RunId(str_repeat('f', 32)), '/srv/elsewhere/rotation');

        $plan = $this->world->rotate($this->world->request(dryRun: true));

        self::assertSame(RotateStatus::DryRun, $plan->status());
        self::assertSame([RefusalReason::RunClaimedElsewhere], $this->reasons($plan));
        $this->assertNothingWritten();
    }

    public function testAResumedRunThatAnotherRunTookTheStoreFromIsRefused(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $waiting = $world->rotate($world->request(probeSettings: $world->probeSettings(waitSeconds: 0)));
        self::assertSame(RotateStatus::AwaitingWebTier, $waiting->status());
        $run = $this->runOf($waiting);
        $world->registry->release($run->id());
        $world->registry->claim(new RunId(str_repeat('f', 32)), '/srv/elsewhere/rotation');
        $world->probe->answerFromNowOn($world->matches());

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RunClaimedElsewhere], $this->reasons($result));
        self::assertSame(RunState::KeyAdded, $world->runs->get($run->id())->state());
    }

    public function testAProbeThatDiffersKeepsTheRunAtKeyAddedAndASecondCallCompletesIt(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $before = $this->storedValues();
        $startedAt = $world->clock->now();

        $waiting = $world->rotate();

        self::assertSame(RotateStatus::AwaitingWebTier, $waiting->status());
        self::assertSame(RunState::KeyAdded, $waiting->state());
        self::assertSame(RunState::KeyAdded, $this->runOf($waiting)->state());
        self::assertTrue($waiting->bearerTokensInvalidated());
        self::assertSame('differs', $waiting->probe()?->status()->value);
        self::assertSame($before, $this->storedValues(), 'No value moves before the web tier holds the key.');
        self::assertCount(1 + 7, $world->probe->observed(), 'The baseline, then one question every 5 s over 30 s.');
        self::assertSame(30, $world->clock->now()->getTimestamp() - $startedAt->getTimestamp());

        $world->probe->answerFromNowOn($world->matches());
        $done = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $done->status());
        self::assertTrue($waiting->runId()?->equals($done->runId() ?? $waiting->runId()));
        self::assertCount(4, $world->config->keyRing()->slots());
        foreach ($world->database->journalEntries() as $entry) {
            self::assertStringStartsWith('3:3:', $entry->newRaw());
        }
        self::assertSame('config secret 1', $world->decryptNow($world->value('core_config_data', 1, 'value', 'config_id')));
    }

    public function testAConflictingWriteKeepsTheNewerValueAndTheNextPassMovesIt(): void
    {
        $world = $this->world;
        $triggered = false;
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $row) use ($world, &$triggered): void {
            if ($triggered || $column->toString() !== 'core_config_data.value' || $row->values() !== ['config_id' => 1]) {
                return;
            }
            $triggered = true;
            $database->update('core_config_data', ['config_id' => 1], 'value', $world->encrypt('changed by the store', 1));
        });

        $result = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        $value = $world->value('core_config_data', 1, 'value', 'config_id');
        self::assertStringStartsWith('3:3:', $value);
        self::assertSame('changed by the store', $world->decryptNow($value));
        self::assertSame(2, $result->reencryption()?->passes());
        self::assertSame([], $result->reencryption()->conflicts());
        self::assertSame(5, $result->reencryption()->appliedTo(new ColumnRef('core_config_data', 'value')));
    }

    public function testAValueTheStoreAlreadyWroteUnderTheNewKeyIsLeftAsItIs(): void
    {
        $world = $this->world;
        $written = null;
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $row) use ($world, &$written): void {
            if ($written !== null || $row->values() !== ['config_id' => 2]) {
                return;
            }
            $newKey = $world->config->keyRing()->slot(3)?->raw() ?? throw new \LogicException('No new key yet.');
            $written = $world->encrypt('written by the store with the new ring', 3, new Key($newKey));
            $database->update('core_config_data', ['config_id' => 2], 'value', $written);
        });

        $result = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertSame($written, $world->value('core_config_data', 2, 'value', 'config_id'));
        self::assertSame(4, $result->reencryption()?->appliedTo(new ColumnRef('core_config_data', 'value')));
    }

    public function testUndecryptableValuesAreLeftUntouchedAndReported(): void
    {
        $world = $this->world;
        $foreign = $world->encrypt('under a foreign key', 1, new Key(KeyMaterial::base64Key()));
        $unsupported = '2:2:' . base64_encode(random_bytes(48));
        $retired = $world->encrypt('under the retired slot', 0, new Key(KeyMaterial::base64Key()));
        $unknown = $world->encrypt('under a slot the ring lacks', 7, new Key(KeyMaterial::base64Key()));
        foreach ([10 => $foreign, 11 => $unsupported, 12 => $retired, 13 => $unknown] as $id => $raw) {
            $world->database->insert('core_config_data', ['config_id' => $id, 'value' => $raw]);
        }

        $result = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        foreach ([10 => $foreign, 11 => $unsupported, 12 => $retired, 13 => $unknown] as $id => $raw) {
            self::assertSame($raw, $world->value('core_config_data', $id, 'value', 'config_id'));
        }
        $column = new ColumnRef('core_config_data', 'value');
        self::assertSame(1, $result->reencryption()?->skippedIn($column, ValueVerdict::AuthenticationFailed));
        self::assertSame(1, $result->reencryption()->skippedIn($column, ValueVerdict::UnsupportedCipher));
        self::assertSame(4, $result->scan()?->summary()->undecryptable());
        foreach ($world->database->journalEntries() as $entry) {
            self::assertNotContains($entry->rowKey()->values()['config_id'] ?? null, [10, 11, 12, 13]);
        }
    }

    public function testARingChangedByAnotherWriterBetweenTwoCallsIsRefusedWithBothFingerprints(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $waiting = $world->rotate();
        $recorded = $this->runOf($waiting)->ringFingerprint();
        $other = $world->ringParser->parse(KeyMaterial::base64Key());
        $world->config->replaceRing($other);
        $writes = count($world->config->writes());
        $world->probe->answerFromNowOn($world->matches());

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RingChanged], $this->reasons($result));
        self::assertStringContainsString($recorded, $this->refusalText($result));
        self::assertStringContainsString($other->fingerprint(), $this->refusalText($result));
        self::assertCount($writes, $world->config->writes());
        self::assertSame($other->fingerprint(), $world->config->keyRing()->fingerprint());
        self::assertSame([], $world->log->eventsStartingWith('db.apply'));
        self::assertSame(RunState::KeyAdded, $this->runOf($result)->state());
    }

    public function testARunThatIsRollingBackIsRefused(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $run = $this->runOf($world->rotate());
        $run->rollingBack($world->clock->now());
        $world->runs->save($run);

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RollbackInProgress], $this->reasons($result));
        self::assertSame(RunState::RollingBack, $result->state());
    }

    public function testASecondPassOverAReencryptedRunMovesOnlyWhatIsStillOld(): void
    {
        $world = $this->world;
        $first = $world->rotate();
        $world->database->update('core_config_data', ['config_id' => 3], 'value', $world->encrypt('straggler', 2));
        $journalBefore = count($world->database->journalEntries());

        $second = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $second->status());
        self::assertTrue($first->runId()?->equals($second->runId() ?? $first->runId()));
        self::assertSame(1, $second->reencryption()?->appliedTotal());
        self::assertCount($journalBefore + 1, $world->database->journalEntries());
        self::assertCount(4, $world->config->keyRing()->slots());
        self::assertSame('straggler', $world->decryptNow($world->value('core_config_data', 3, 'value', 'config_id')));
    }

    public function testTheLockIsHeldForTheCallAndReleasedAfterIt(): void
    {
        $world = $this->world;
        $other = $world->runs->concurrentHandle();
        $other->lock();
        try {
            $world->rotate();
            self::fail('The rotation ran while another process held the lock.');
        } catch (RunLocked) {
            $this->addToAssertionCount(1);
        }
        $other->unlock();

        $world->probe->enqueue($world->differs());
        $world->rotate();

        $other->lock();
        $other->unlock();
        $this->addToAssertionCount(1);
    }

    public function testTheResultAndTheProgressCarryNoSecret(): void
    {
        $world = $this->world;

        $result = $world->rotate();

        $text = print_r($result, true) . $world->progress->transcript() . $this->refusalText($result);
        foreach ([...$world->plaintexts(), $world->key(1)->raw(), $world->key(2)->raw(), (string) $world->config->keyRing()->slot(3)?->raw()] as $secret) {
            self::assertStringNotContainsString($secret, $text);
        }
    }

    private function assertNothingWritten(): void
    {
        self::assertSame([], $this->world->config->writes());
        self::assertSame($this->world->ringBefore->fingerprint(), $this->world->config->keyRing()->fingerprint());
        self::assertNull($this->world->runs->latest());
        self::assertFalse($this->world->database->journalExists());
        self::assertSame(0, $this->world->cache->calls());
        self::assertSame([], $this->world->log->eventsStartingWith('store.'));
        self::assertSame([], $this->world->log->eventsStartingWith('db.'));
    }

    private function runOf(RotateResult $result): RotationRun
    {
        $id = $result->runId() ?? throw new \LogicException('The result names no run: ' . $this->refusalText($result));

        return $this->world->runs->get($id);
    }

    /**
     * @return array<string, string> `table.column{row key}` => stored value
     */
    private function storedValues(): array
    {
        $values = [];
        foreach (['core_config_data' => ['config_id', 'value'], 'oauth_consumer' => ['entity_id', 'secret']] as $table => [$key, $column]) {
            foreach ($this->world->database->rows($table) as $row) {
                $values[$table . '.' . $column . (new RowKey([$key => $row[$key] ?? 0]))->toJson()] = (string) ($row[$column] ?? '');
            }
        }

        return $values;
    }

    /**
     * @return list<RefusalReason>
     */
    private function reasons(RotateResult $result): array
    {
        return array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $result->refusals());
    }

    private function refusalText(RotateResult $result): string
    {
        return implode("\n", array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals()));
    }

    /**
     * @return list<RunOverride>
     */
    private function overrides(RotationRun $run): array
    {
        return array_column($run->overrides(), 'override');
    }
}
