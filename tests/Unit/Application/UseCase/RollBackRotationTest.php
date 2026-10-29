<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * A rollback brings the store back to the key ring it had before the run, from every state the run can
 * be in: every value is back under that ring, either as its very bytes from before the run or, where the
 * store changed it meanwhile, as the store's plaintext under the key that was active before the run.
 */
final class RollBackRotationTest extends TestCase
{
    private LifecycleWorld $life;

    /**
     * @var array<string, array<string, string>> `table#id` => column => value before the run
     */
    private array $beforeRun = [];

    protected function setUp(): void
    {
        $this->life = new LifecycleWorld();
        $this->life->world->seedDefault();
        foreach (['core_config_data' => 'config_id', 'oauth_consumer' => 'entity_id'] as $table => $keyColumn) {
            foreach ($this->life->world->database->rows($table) as $row) {
                $this->beforeRun[$table . '#' . (string) $row[$keyColumn]] = ['value' => (string) ($row[$this->column($table)] ?? '')];
            }
        }
    }

    protected function tearDown(): void
    {
        $this->life->cleanUp();
    }

    /**
     * @return array<string, array{\Closure(LifecycleWorld): void, RunState}>
     */
    public static function runStates(): array
    {
        return [
            'key_pending, the key written' => [static function (LifecycleWorld $life): void {
                $world = $life->world;
                $world->config->afterWrite(static function () use ($world): void {
                    $world->config->afterWrite(null);

                    throw new \RuntimeException('crash after the key write');
                });
                self::crashed(static fn() => $world->rotate(), $life);
            }, RunState::KeyPending],
            'key_added, the web tier not confirmed' => [static function (LifecycleWorld $life): void {
                $world = $life->world;
                $world->probe->enqueue($world->matches());
                $world->probe->answerFromNowOn($world->differs());
                $result = $world->rotate($world->request(probeSettings: $world->probeSettings(waitSeconds: 0)));
                self::assertSame(RotateStatus::AwaitingWebTier, $result->status());
                $world->probe->answerFromNowOn($world->matches());
            }, RunState::KeyAdded],
            'web_confirmed, interrupted after a batch' => [static function (LifecycleWorld $life): void {
                $world = $life->world;
                $writes = 0;
                $world->database->beforeEachWrite(static function () use ($world, &$writes): void {
                    if (++$writes === 3) {
                        $world->database->beforeEachWrite(null);

                        throw new \RuntimeException('crash after the first batch');
                    }
                });
                self::crashed(static fn() => $world->rotate($world->request(batchSize: 2)), $life);
            }, RunState::WebConfirmed],
            'reencrypted' => [static function (LifecycleWorld $life): void {
                $life->rotate();
            }, RunState::Reencrypted],
            'retire_pending, the placeholders written' => [static function (LifecycleWorld $life): void {
                $life->rotate();
                $life->deployCommittedUnderNewKey();
                $world = $life->world;
                $world->config->afterWrite(static function (KeyRing $ring) use ($world): void {
                    if ($ring->slot(1)?->isRetired() === true) {
                        $world->config->afterWrite(null);

                        throw new \RuntimeException('crash after the placeholder write');
                    }
                });
                self::crashed(static fn() => $life->retire(), $life);
                $life->deployCommittedUnderOldKey();
            }, RunState::RetirePending],
            'retired' => [static function (LifecycleWorld $life): void {
                $life->rotateAndRetire();
                $life->deployCommittedUnderOldKey();
            }, RunState::Retired],
        ];
    }

    /**
     * @param \Closure(LifecycleWorld): void $arrange
     */
    #[DataProvider('runStates')]
    public function testEveryValueIsBackUnderTheRingBeforeTheRun(\Closure $arrange, RunState $state): void
    {
        $life = $this->life;
        $world = $life->world;
        $arrange($life);
        self::assertSame($state, $life->run()->state());
        $active = $world->config->keyRing();
        $activeKey = $active->active(new DirectKeyFactory());
        $world->database->update('oauth_consumer', ['entity_id' => 1], 'secret', $world->encrypt('consumer secret changed', $active->activeIndex(), $activeKey));
        $world->database->insert('oauth_consumer', ['entity_id' => 4, 'secret' => $world->encrypt('consumer secret added', $active->activeIndex(), $activeKey), 'updated_at' => 0]);

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        self::assertSame($state, $result->rolledBackFrom());
        foreach ($this->beforeRun as $location => $before) {
            [$table, $id] = explode('#', $location);
            $now = $this->valueAt($table, (int) $id);
            if ($location === 'oauth_consumer#1') {
                $this->assertUnderTheRingBeforeTheRun('consumer secret changed', $now, $location);
            } else {
                self::assertSame($before['value'], $now, sprintf('%s holds its bytes from before the run.', $location));
            }
        }
        $this->assertUnderTheRingBeforeTheRun('consumer secret added', $this->valueAt('oauth_consumer', 4), 'oauth_consumer#4');
        $env = $world->config->systemValues()[0]->ciphertext();
        $this->assertUnderTheRingBeforeTheRun('env secret', $env->toString(), 'the deployment configuration value');
        self::assertSame(RollBackRotation::BEARER_TOKEN_NOTE, $result->bearerTokenNote());
    }

    public function testFromRetiredTheOldKeysAreRestoredAndTheWebTierHoldsThemBeforeAnyValueIsReverted(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $restored = $world->config->keyRing();
        $life->deployCommittedUnderNewKey();
        self::assertSame(RetireStatus::Retired, $life->retire()->status());
        $life->deployCommittedUnderOldKey();
        $logBefore = count($world->log->events());

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        $events = array_slice($world->log->events(), $logBefore);
        $restoreWrite = $this->position($events, 'config.write ' . $restored->fingerprint());
        $probe = $this->position($events, 'probe.observe ' . $restored->fingerprint());
        $firstMove = $this->firstOf($events, ['db.revert', 'db.supersede', 'db.apply back']);
        self::assertNotNull($restoreWrite, 'The retired keys are written back first.');
        self::assertNotNull($probe, 'The web tier is asked about the restored ring.');
        self::assertNotNull($firstMove);
        self::assertLessThan($probe, $restoreWrite);
        self::assertLessThan($firstMove, $probe, 'The web tier holds the restored keys before any value moves onto them.');
        self::assertSame($world->ringBefore->slot(1)?->raw(), $restored->slot(1)?->raw());
    }

    public function testAValueTheStoreRewroteUnderTheNewKeyIsMovedBackAndItsEntryIsNotReportedAgain(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $world->database->update('core_config_data', ['config_id' => 1], 'value', $world->encrypt('config secret changed', $life->newIndex(), $life->newKey()));
        $world->config->afterWrite(static function () use ($world): void {
            $world->config->afterWrite(null);

            throw new \RuntimeException('crash after the deployment configuration values');
        });

        self::crashed(fn() => $life->rollBack(), $life);

        self::assertSame(RunState::RollingBack, $life->run()->state());
        $this->assertUnderTheRingBeforeTheRun('config secret changed', $this->valueAt('core_config_data', 1), 'the rewritten value', $world->ringBefore);

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        self::assertSame(0, $result->journal()?->superseded(), 'The superseded entry is settled.');
        self::assertSame([], $result->journal()->leftAlone(), 'The superseded entry is not reported on the re-run.');
        $this->assertUnderTheRingBeforeTheRun('config secret changed', $this->valueAt('core_config_data', 1), 'the rewritten value');
    }

    public function testAnEntryWhoseRowNowHoldsSomethingElseIsLeftAloneAndReported(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $world->database->update('core_config_data', ['config_id' => 5], 'value', 'set in plain text');

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        $leftAlone = $result->journal()?->leftAlone() ?? [];
        self::assertCount(1, $leftAlone);
        self::assertSame(['config_id' => 5], $leftAlone[0]->rowKey()->values());
        self::assertSame('set in plain text', $this->valueAt('core_config_data', 5), 'The store\'s newer value is kept.');
    }

    public function testRunningRollbackAgainDoesNothing(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotateAndRetire();
        $life->deployCommittedUnderOldKey();
        $this->assertRolledBack($life->rollBack());
        $writes = count($world->config->writes());
        $journal = count($world->database->journalEntries());
        $events = count($world->log->events());

        $again = $life->rollBack();

        self::assertSame(RollBackStatus::AlreadyRolledBack, $again->status());
        self::assertSame($life->runId()->toString(), $again->runId()?->toString());
        self::assertCount($writes, $world->config->writes());
        self::assertCount($journal, $world->database->journalEntries());
        self::assertCount($events, $world->log->events(), 'Nothing is read from the web tier or written anywhere.');
    }

    public function testWhileRollingBackRotateRetireAndPurgeRefuse(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $writtenAt = $life->run()->lastRingWriteAt() ?? throw new \LogicException('The rotation wrote no ring.');
        $world->workers->start('php bin/magento indexer:reindex', $writtenAt->modify('-5 minutes'));

        $refused = $life->rollBack();

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::WorkersRunning], $this->reasons($refused->refusals()));
        self::assertSame(RunState::RollingBack, $life->run()->state(), 'The rollback is recorded before anything else.');

        $rotate = $world->rotate();
        self::assertSame(RotateStatus::Refused, $rotate->status());
        self::assertSame([RefusalReason::RollbackInProgress], $this->reasons($rotate->refusals()));
        $retire = $life->retire();
        self::assertSame(RetireStatus::Refused, $retire->status());
        self::assertSame([RefusalReason::RollbackInProgress], $this->reasons($retire->refusals()));
        self::assertSame([RefusalReason::RollbackInProgress], $this->reasons($life->purge()->refusals()));

        $world->workers->replace([]);
        $this->assertRolledBack($life->rollBack());
    }

    public function testAWorkerStartedAfterTheKeyWriteAndStillRunningRefusesTheRemovalOfTheNewSlot(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $writtenAt = $life->run()->lastRingWriteAt() ?? throw new \LogicException('The rotation wrote no ring.');
        $world->clock->sleep(600);
        $world->workers->start('php bin/magento queue:consumers:start async.operations.all', $writtenAt->modify('+1 minute'));

        $refused = $life->rollBack();

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::WorkersRunning], $this->reasons($refused->refusals()));
        self::assertStringContainsString('queue:consumers:start', $refused->refusals()[0]->message());
        self::assertNotNull($world->config->keyRing()->slot($newIndex), 'A process holding the ring with the new key as its active key keeps it.');
        self::assertSame(RunState::RollingBack, $life->run()->state());

        $world->workers->replace([]);
        $this->assertRolledBack($life->rollBack());
    }

    public function testIgnoringWorkersLetsTheRollbackRemoveTheNewSlotAndIsRecorded(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $writtenAt = $life->run()->lastRingWriteAt() ?? throw new \LogicException('The rotation wrote no ring.');
        $world->clock->sleep(600);
        $world->workers->start('php bin/magento cron:run', $writtenAt->modify('+1 minute'));

        $this->assertRolledBack($life->rollBack($life->rollBackRequest(ignoreWorkers: true)));
        self::assertContains('ignore_workers', array_map(static fn(array $entry): string => $entry['override']->value, $life->run()->overrides()));
    }

    public function testRefusesToRemoveTheNewKeyWhileTheCommittedConfigurationHoldsAValueUnderIt(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotateAndRetire();
        $newIndex = $life->newIndex();

        $refused = $life->rollBack();

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::CommittedValuesOnRemovedKey], $this->reasons($refused->refusals()));
        self::assertStringContainsString(implode('/', RotationWorld::COMMITTED_PATH), $refused->refusals()[0]->message());
        self::assertNotNull($world->config->keyRing()->slot($newIndex), 'The new key stays while a deployed value needs it.');
        self::assertSame(RunState::RollingBack, $life->run()->state());

        $life->deployCommittedUnderOldKey();
        $this->assertRolledBack($life->rollBack());
    }

    public function testAValueUnderTheNewKeyInATableWithoutARowKeyRefusesTheRemovalOfTheNewSlot(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $world->database->createTable('legacy_token', [], ['token']);
        $world->database->insert('legacy_token', ['token' => $world->encrypt('keyless secret', $newIndex, $life->newKey())]);

        $refused = $life->rollBack($life->rollBackRequest(acceptEmbedded: true));

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::RollbackBlocked], $this->reasons($refused->refusals()));
        self::assertStringContainsString('legacy_token.token', $refused->refusals()[0]->message());
        self::assertNotNull($world->config->keyRing()->slot($newIndex), 'The new key stays while a value only it reads remains.');
        self::assertSame(RunState::RollingBack, $life->run()->state());

        $world->database->delete('legacy_token', []);
        $this->assertRolledBack($life->rollBack());
    }

    public function testAValueTheStoreKeepsRewritingUnderTheNewKeyRefusesTheRemovalOfTheNewSlot(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $newKey = $life->newKey();
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $rowKey) use ($world, $newIndex, $newKey): void {
            if ($column->table() === 'oauth_consumer' && $rowKey->values() === ['entity_id' => 1]) {
                $database->update('oauth_consumer', ['entity_id' => 1], 'secret', $world->encrypt('consumer secret busy', $newIndex, $newKey));
            }
        });

        $refused = $life->rollBack();

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::RollbackBlocked], $this->reasons($refused->refusals()));
        self::assertStringContainsString('1 in the database', $refused->refusals()[0]->message());
        self::assertNotNull($world->config->keyRing()->slot($newIndex));
        self::assertSame(RunState::RollingBack, $life->run()->state());

        $world->database->beforeEachWrite(null);
        $this->assertRolledBack($life->rollBack());
        $this->assertUnderTheRingBeforeTheRun('consumer secret busy', $this->valueAt('oauth_consumer', 1), 'the value the store rewrote');
    }

    public function testEmbeddedValuesRefuseTheRemovalOfTheNewSlotUntilTheyAreAcknowledged(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $newIndex = $life->newIndex();
        $world->database->createTable('sales_payment', ['entity_id'], ['additional_information']);
        $world->database->insert('sales_payment', [
            'entity_id' => 1,
            'additional_information' => json_encode(['token' => $world->encrypt('embedded secret', $newIndex, $life->newKey())], JSON_THROW_ON_ERROR),
        ]);

        $refused = $life->rollBack();

        self::assertSame([RefusalReason::RollbackBlocked], $this->reasons($refused->refusals()));
        self::assertStringContainsString('1 embedded values', $refused->refusals()[0]->message());
        self::assertNotNull($world->config->keyRing()->slot($newIndex));

        $this->assertRolledBack($life->rollBack($life->rollBackRequest(acceptEmbedded: true)));
        self::assertContains('accept_embedded', array_map(static fn(array $entry): string => $entry['override']->value, $life->run()->overrides()));
    }

    public function testWhileAnotherRunHoldsTheStoreTheRollbackRefusesBeforeRecordingAnything(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $world->registry->release($life->runId());
        $world->registry->claim(new RunId(str_repeat('f', 32)), '/srv/elsewhere/rotation');
        $writes = count($world->config->writes());

        $refused = $life->rollBack();

        self::assertSame(RollBackStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::RunClaimedElsewhere], $this->reasons($refused->refusals()));
        self::assertStringContainsString('/srv/elsewhere/rotation', $refused->refusals()[0]->message());
        self::assertSame(RunState::Reencrypted, $life->run()->state(), 'Not even the rollback is recorded.');
        self::assertCount($writes, $world->config->writes());
    }

    public function testAnUnfinishedRunIsNeededToRollBack(): void
    {
        $result = $this->life->rollBack();

        self::assertSame(RollBackStatus::Refused, $result->status());
        self::assertSame([RefusalReason::NoRun], $this->reasons($result->refusals()));
    }

    /**
     * Runs the step, which must crash, then releases the lock the crashed process held.
     *
     * @param \Closure(): mixed $step
     */
    public static function crashed(\Closure $step, LifecycleWorld $life): void
    {
        try {
            $step();
            self::fail('The step was expected to crash.');
        } catch (\RuntimeException $crash) {
            self::assertStringStartsWith('crash', $crash->getMessage());
        } finally {
            $life->world->runs->unlock();
        }
    }

    private function assertRolledBack(RollBackResult $result): void
    {
        $life = $this->life;
        self::assertSame(
            RollBackStatus::RolledBack,
            $result->status(),
            implode(' | ', array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals())),
        );
        self::assertSame(RunState::RolledBack, $life->run()->state());
        self::assertSame($life->world->ringBefore->fingerprint(), $life->world->config->keyRing()->fingerprint(), 'The deployment configuration holds the ring before the run.');
        self::assertSame($life->world->ringBefore->fingerprint(), $result->ringFingerprint());
    }

    private function assertUnderTheRingBeforeTheRun(string $plaintext, string $raw, string $what, ?KeyRing $ring = null): void
    {
        $world = $this->life->world;
        $ring ??= $world->ringBefore;
        $ciphertext = $world->ciphertextParser->parse($raw);
        self::assertNotNull($ciphertext, $what);
        self::assertLessThanOrEqual($ring->activeIndex(), $ciphertext->keyIndex(), sprintf('%s is under a key of the ring before the run.', $what));
        $key = $ring->slot($ciphertext->keyIndex())?->key(new DirectKeyFactory());
        self::assertNotNull($key, $what);
        self::assertSame($plaintext, $world->cipher->decrypt($ciphertext, $key)?->bytes(), $what);
    }

    private function valueAt(string $table, int $id): string
    {
        return $this->life->world->value($table, $id, $this->column($table), $table === 'core_config_data' ? 'config_id' : 'entity_id');
    }

    private function column(string $table): string
    {
        return $table === 'core_config_data' ? 'value' : 'secret';
    }

    /**
     * @param list<Refusal> $refusals
     *
     * @return list<RefusalReason>
     */
    private function reasons(array $refusals): array
    {
        return array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $refusals);
    }

    /**
     * @param list<string> $events
     */
    private function position(array $events, string $prefix): ?int
    {
        foreach ($events as $position => $event) {
            if (str_starts_with($event, $prefix)) {
                return $position;
            }
        }

        return null;
    }

    /**
     * @param list<string> $events
     * @param list<string> $prefixes
     */
    private function firstOf(array $events, array $prefixes): ?int
    {
        foreach ($events as $position => $event) {
            foreach ($prefixes as $prefix) {
                if (str_starts_with($event, $prefix)) {
                    return $position;
                }
            }
        }

        return null;
    }
}
