<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use PHPUnit\Framework\TestCase;

/**
 * Retiring the old keys replaces them by placeholders only once no stored value needs them, keeps
 * everything the retirement replaces before it writes, and moves the stragglers written while the ring
 * changed with the keys it kept.
 */
final class RetireOldKeysTest extends TestCase
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

    public function testTheKeysAndPlaceholdersAreKeptBeforeTheRingWriteAndTheMovedIndicesAreRetired(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $ringBeforeRetire = $world->config->keyRing();
        $atWrite = null;
        $world->config->afterWrite(function (KeyRing $ring) use ($life, &$atWrite): void {
            if ($ring->slot(1)?->isRetired() === true) {
                $atWrite = [
                    'state' => $life->run()->state(),
                    'keys' => $this->entries($life->world->runs->keptKeys($life->runId(), KeptKeyRole::Retired)),
                    'placeholders' => $this->entries($life->world->runs->keptPlaceholders($life->runId())),
                ];
            }
        });

        $result = $life->retire();

        self::assertSame(RetireStatus::Retired, $result->status(), $this->explain($result));
        self::assertSame(RunState::Retired, $life->run()->state());
        self::assertNotNull($atWrite, 'The placeholder ring was written.');
        self::assertSame(RunState::RetirePending, $atWrite['state'], 'retire_pending is saved before the ring write.');
        self::assertSame(
            [1 => $ringBeforeRetire->slot(1)?->raw(), 2 => $ringBeforeRetire->slot(2)?->raw()],
            $atWrite['keys'],
            'Every replaced key is kept before the ring write.',
        );
        $ring = $world->config->keyRing();
        self::assertSame([1 => $ring->slot(1)?->raw(), 2 => $ring->slot(2)?->raw()], $atWrite['placeholders'], 'The placeholders written are the ones kept before the write.');
        self::assertTrue($ring->slot(1)?->isRetired());
        self::assertTrue($ring->slot(2)?->isRetired());
        self::assertSame($ringBeforeRetire->slot(0)?->raw(), $ring->slot(0)?->raw(), 'A slot retired before the run is left as it was.');
        self::assertSame($ringBeforeRetire->slot(3)?->raw(), $ring->slot(3)?->raw(), 'The active key is never retired.');
        self::assertSame([1, 2], $result->retiredIndices());
        self::assertSame($ring->fingerprint(), $life->run()->ringFingerprint());
        self::assertSame(0, $result->scan()?->summary()->verifiedOnAny([1, 2]));
        foreach ($world->seeded() as $location => $plaintext) {
            [$table, $id] = explode('#', $location);
            $keyColumn = $table === 'core_config_data' ? 'config_id' : 'entity_id';
            self::assertSame($plaintext, $world->decryptNow($world->value($table, (int) $id, $this->column($table), $keyColumn)), $location);
        }
    }

    public function testAStragglerWrittenBetweenTheRingWriteAndTheRescanIsMovedWithTheKeptKeyBeforeTheCacheIsCleaned(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->config->afterWrite(function (KeyRing $ring) use ($world): void {
            if ($ring->slot(1)?->isRetired() === true) {
                $world->config->afterWrite(null);
                $world->seed('core_config_data', 9, 'value', 'late secret', 2, 'config_id');
            }
        });
        $logBefore = count($world->log->events());

        $result = $life->retire();

        self::assertSame(RetireStatus::Retired, $result->status(), $this->explain($result));
        self::assertSame(1, $result->stragglersAfterWrite()?->appliedTotal());
        $straggler = $world->value('core_config_data', 9, 'value', 'config_id');
        self::assertStringStartsWith($life->newIndex() . ':', $straggler);
        self::assertSame('late secret', $world->decryptNow($straggler), 'The straggler decrypts under the ring with the placeholders.');

        $events = array_slice($world->log->events(), $logBefore);
        $ringWrite = $this->firstPosition($events, 'config.write ' . $world->config->keyRing()->fingerprint());
        $fix = $this->lastPosition($events, 'db.apply forward 1');
        $clean = $this->lastPosition($events, 'cache.clean');
        self::assertNotNull($ringWrite);
        self::assertNotNull($fix);
        self::assertNotNull($clean);
        self::assertLessThan($fix, $ringWrite, 'The straggler is moved after the ring write.');
        self::assertLessThan($clean, $fix, 'The cache is cleaned after the straggler is moved.');
    }

    public function testRefusesWhileTheCommittedConfigurationHoldsAValueOnAMovedIndex(): void
    {
        $this->life->rotate();

        $result = $this->life->retire();

        $this->assertRefusedWithoutWriting($result, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('in the committed configuration', $result->refusals()[0]->message());
    }

    public function testRefusesWhileTheDeploymentConfigurationHoldsAValueOnAMovedIndex(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->config->putSystemValue(new SystemValue(['payment', 'stray', 'secret'], $world->ciphertext('stray secret', 2), SystemValueSource::Env));
        $world->config->afterWrite(function () use ($world): void {
            $world->config->afterWrite(null);
            $world->config->putSystemValue(new SystemValue(['payment', 'late', 'secret'], $world->ciphertext('late secret', 1), SystemValueSource::Env));
        });

        $result = $life->retire();

        $this->assertRefusedWithoutWriting($result, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('1 in the deployment configuration', $result->refusals()[0]->message());
    }

    public function testRefusesWhileTheDatabaseHoldsAValueOnAMovedIndex(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->seed('core_config_data', 9, 'value', 'busy secret', 1, 'config_id');
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $rowKey) use ($world): void {
            if ($rowKey->values() === ['config_id' => 9]) {
                $database->update('core_config_data', ['config_id' => 9], 'value', $world->encrypt('busy secret again', 1));
            }
        });

        $result = $life->retire();

        $this->assertRefusedWithoutWriting($result, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('1 in the database', $result->refusals()[0]->message());
    }

    public function testRefusesUnacknowledgedEmbeddedValuesAndRetiresOnceTheyAreAcknowledged(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->database->createTable('sales_payment', ['entity_id'], ['additional_information']);
        $world->database->insert('sales_payment', [
            'entity_id' => 1,
            'additional_information' => json_encode(['token' => $world->encrypt('embedded secret', $life->newIndex(), $life->newKey())], JSON_THROW_ON_ERROR),
        ]);

        $refused = $life->retire();

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('1 embedded values', $refused->refusals()[0]->message());

        $accepted = $life->retire($life->retireRequest(acceptEmbedded: true));

        self::assertSame(RetireStatus::Retired, $accepted->status(), $this->explain($accepted));
        self::assertContains(RunOverride::AcceptEmbedded, $this->overrides());
    }

    public function testAValueOnAMovedIndexInATableWithoutARowKeyRefusesTheRetirementEvenWithEmbeddedValuesAccepted(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->database->createTable('legacy_token', [], ['token']);
        $world->database->insert('legacy_token', ['token' => $world->encrypt('keyless secret', 1)]);

        $refused = $life->retire($life->retireRequest(acceptEmbedded: true));

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::RetireBlocked]);
        $message = $refused->refusals()[0]->message();
        self::assertStringContainsString('1 values under the old key indices', $message);
        self::assertStringContainsString('no row key', $message);
        self::assertStringContainsString('legacy_token.token', $message);
        self::assertNotContains(RunOverride::AcceptEmbedded, $this->overrides());

        $world->database->delete('legacy_token', []);

        self::assertSame(RetireStatus::Retired, $life->retire()->status());
    }

    public function testRefusesAColumnWhoseScanWasCutShortUntilItIsAcknowledged(): void
    {
        $life = $this->life;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $life->world->database->cutScanShort('oauth_consumer', 'secret');

        $refused = $life->retire();

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('1 columns whose scan was cut short', $refused->refusals()[0]->message());
        self::assertSame(RetireStatus::Retired, $life->retire($life->retireRequest(acceptEmbedded: true))->status());
    }

    public function testRefusesWhenTheConfigurationCacheWasNotCleanedAfterTheReencryption(): void
    {
        $life = $this->life;
        $world = $life->world;
        $world->cache->answerFromNowOn(new CacheCleanOutcome(false, 'The cache backend did not answer.'));
        $life->rotate();
        $world->cache->answerFromNowOn(new CacheCleanOutcome(true, ''));
        $life->deployCommittedUnderNewKey();

        $refused = $life->retire();

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::RetireBlocked]);
        self::assertStringContainsString('configuration cache was not cleaned', $refused->refusals()[0]->message());

        $manual = $life->retire($life->retireRequest(cacheCleanedManually: true));

        self::assertSame(RetireStatus::Retired, $manual->status(), $this->explain($manual));
        self::assertContains(RunOverride::CacheCleanedManually, $this->overrides());
    }

    public function testRefusesWhenTheCacheCannotBeCleanedAfterStragglersMovedUnlessItWasCleanedByHand(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->seed('core_config_data', 9, 'value', 'late secret', 2, 'config_id');
        $world->cache->answerFromNowOn(new CacheCleanOutcome(false, 'The cache backend did not answer.'));

        $refused = $life->retire();

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::CacheNotCleaned]);
        self::assertStringStartsWith($life->newIndex() . ':', $world->value('core_config_data', 9, 'value', 'config_id'), 'The straggler moved before the refusal.');
        self::assertFalse($life->run()->configCacheCleaned());

        self::assertSame(RetireStatus::Retired, $life->retire($life->retireRequest(cacheCleanedManually: true))->status());
    }

    public function testRefusesWhileAWorkerOlderThanTheRotationRingWriteRuns(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $writtenAt = $life->run()->lastRingWriteAt() ?? throw new \LogicException('The rotation wrote no ring.');
        $world->workers->start('php bin/magento queue:consumers:start async.operations.all', $writtenAt->modify('-1 minute'));

        $refused = $life->retire();

        $this->assertRefusedWithoutWriting($refused, [RefusalReason::WorkersRunning]);
        self::assertCount(1, $refused->workers());

        $world->workers->replace([]);
        $world->workers->start('php bin/magento cron:run', $writtenAt->modify('+1 second'));

        self::assertSame(RetireStatus::Retired, $life->retire()->status(), 'A process started after the rotation ring write holds the new key.');
    }

    public function testRefusesWhileAnotherRunHoldsTheStore(): void
    {
        $life = $this->life;
        $world = $life->world;
        $life->rotate();
        $life->deployCommittedUnderNewKey();
        $world->registry->release($life->runId());
        $world->registry->claim(new RunId(str_repeat('f', 32)), '/srv/elsewhere/rotation');

        $result = $life->retire();

        $this->assertRefusedWithoutWriting($result, [RefusalReason::RunClaimedElsewhere]);
        self::assertStringContainsString(str_repeat('f', 32), $result->refusals()[0]->message());
    }

    public function testRefusesWithoutARun(): void
    {
        $result = $this->life->retire();

        self::assertSame(RetireStatus::Refused, $result->status());
        self::assertSame([RefusalReason::NoRun], $this->reasons($result));
    }

    public function testRefusesARunWhoseValuesHaveNotMovedYet(): void
    {
        $world = $this->life->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $world->rotate($world->request(probeSettings: $world->probeSettings(waitSeconds: 0)));

        $result = $this->life->retire();

        self::assertSame([RefusalReason::StateDoesNotAllow], $this->reasons($result));
        self::assertSame(RunState::KeyAdded, $this->life->run()->state());
    }

    /**
     * @param list<RefusalReason> $reasons
     */
    private function assertRefusedWithoutWriting(RetireResult $result, array $reasons): void
    {
        $life = $this->life;
        self::assertSame(RetireStatus::Refused, $result->status());
        self::assertSame($reasons, $this->reasons($result), $this->explain($result));
        self::assertSame(RunState::Reencrypted, $life->run()->state());
        self::assertSame($life->run()->ringFingerprint(), $life->world->config->keyRing()->fingerprint(), 'The key ring is not written.');
        self::assertSame([], $life->world->runs->keptPlaceholders($life->runId()), 'No placeholder is kept.');
        self::assertSame([], $life->world->runs->keptKeys($life->runId(), KeptKeyRole::Retired), 'No key is kept as retired.');
    }

    /**
     * @return list<RefusalReason>
     */
    private function reasons(RetireResult $result): array
    {
        return array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $result->refusals());
    }

    /**
     * @return list<RunOverride>
     */
    private function overrides(): array
    {
        return array_map(static fn(array $entry): RunOverride => $entry['override'], $this->life->run()->overrides());
    }

    private function explain(RetireResult $result): string
    {
        return implode(' | ', array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals()));
    }

    /**
     * @param list<KeySlot> $slots
     *
     * @return array<int, string>
     */
    private function entries(array $slots): array
    {
        $entries = [];
        foreach ($slots as $slot) {
            $entries[$slot->index()] = $slot->raw();
        }

        return $entries;
    }

    private function column(string $table): string
    {
        return $table === 'core_config_data' ? 'value' : 'secret';
    }

    /**
     * @param list<string> $events
     */
    private function firstPosition(array $events, string $prefix): ?int
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
     */
    private function lastPosition(array $events, string $prefix): ?int
    {
        $last = null;
        foreach ($events as $position => $event) {
            if (str_starts_with($event, $prefix)) {
                $last = $position;
            }
        }

        return $last;
    }
}
