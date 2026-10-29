<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use PHPUnit\Framework\TestCase;

/**
 * A rollback interrupted at any step is finished by running it again: every step reads the store as it
 * is now, so a step already done is found done and is not done twice, and a slot is only ever removed
 * when it holds the key the run appended.
 */
final class RollBackRotationResumeTest extends TestCase
{
    private ?LifecycleWorld $life = null;

    protected function tearDown(): void
    {
        $this->life?->cleanUp();
    }

    public function testACrashAfterTheSlotRemovalOnARingWithAUsableFirstSlotKeepsThePreviousActiveKey(): void
    {
        $life = $this->world(usableFirstSlot: true);
        $world = $life->world;
        $life->rotate();
        $world->config->afterWrite(static function (KeyRing $ring) use ($world): void {
            if ($ring->fingerprint() === $world->ringBefore->fingerprint()) {
                $world->config->afterWrite(null);

                throw new \RuntimeException('crash after the slot removal');
            }
        });

        RollBackRotationTest::crashed(static fn() => $life->rollBack(), $life);

        self::assertSame(RunState::RollingBack, $life->run()->state());
        self::assertSame($world->ringBefore->fingerprint(), $world->config->keyRing()->fingerprint());
        $writes = count($world->config->writes());

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        $ring = $world->config->keyRing();
        self::assertCount(3, $ring->slots(), 'The slot that was active before the run is still there.');
        self::assertSame($world->ringBefore->slot(2)?->raw(), $ring->slot(2)?->raw());
        self::assertSame($world->ringBefore->slot(0)?->raw(), $ring->slot(0)?->raw());
        self::assertCount($writes, $world->config->writes(), 'The ring already equals the ring before the run; no slot is removed.');
        foreach ($world->seeded() as $location => $plaintext) {
            [$table, $id] = explode('#', $location);
            $raw = $table === 'core_config_data'
                ? $world->value($table, (int) $id, 'value', 'config_id')
                : $world->value($table, (int) $id, 'secret');
            self::assertSame($plaintext, $world->decryptNow($raw), $location);
        }
    }

    public function testACrashAfterTheKeyRestoreButBeforeTheProbeAsksTheWebTierBeforeAnyValueMoves(): void
    {
        $life = $this->world();
        $world = $life->world;
        $life->rotate();
        $restored = $world->config->keyRing()->fingerprint();
        $life->retireRotated();
        $life->deployCommittedUnderOldKey();
        $world->config->afterWrite(static function (KeyRing $ring) use ($world, $restored): void {
            if ($ring->fingerprint() === $restored) {
                $world->config->afterWrite(null);

                throw new \RuntimeException('crash after the key restore');
            }
        });

        RollBackRotationTest::crashed(static fn() => $life->rollBack(), $life);

        self::assertSame(RunState::RollingBack, $life->run()->state());
        self::assertSame($restored, $world->config->keyRing()->fingerprint(), 'The retired keys are back in the file.');
        self::assertSame($restored, $life->run()->intendedRingFingerprint(), 'The restore was announced, its write not yet recorded.');
        $logBefore = count($world->log->events());

        $result = $life->rollBack();

        $this->assertRolledBack($result);
        $events = array_slice($world->log->events(), $logBefore);
        $probe = array_search('probe.observe ' . $restored, $events, true);
        $firstMove = null;
        foreach ($events as $position => $event) {
            if (str_starts_with($event, 'db.revert') || str_starts_with($event, 'db.supersede') || str_starts_with($event, 'db.apply')) {
                $firstMove = $position;
                break;
            }
        }
        self::assertIsInt($probe, 'The resumed rollback asks the web tier about the restored ring.');
        self::assertIsInt($firstMove);
        self::assertLessThan($firstMove, $probe, 'The web tier holds the restored keys before any value moves.');
        $restores = array_filter(
            $world->config->writes(),
            static fn(array $write): bool => $write['ring']->fingerprint() === $restored && $write['expected'] !== $restored,
        );
        self::assertCount(2, $restores, 'The ring with the retired keys is written by the rotation and once by the rollback, never again.');
    }

    public function testARestoreTheWebTierDoesNotConfirmStopsBeforeAnyValueMovesAndIsContinuedByRunningRollbackAgain(): void
    {
        $life = $this->world();
        $world = $life->world;
        $life->rotate();
        $life->retireRotated();
        $life->deployCommittedUnderOldKey();
        $world->probe->answerFromNowOn($world->differs());
        $logBefore = count($world->log->events());

        $waiting = $life->rollBack($life->rollBackRequest(probeSettings: $world->probeSettings(waitSeconds: 10)));

        self::assertSame(RollBackStatus::AwaitingWebTier, $waiting->status());
        self::assertSame(RunState::RollingBack, $life->run()->state());
        $events = array_slice($world->log->events(), $logBefore);
        self::assertSame([], array_values(array_filter($events, static fn(string $event): bool => str_starts_with($event, 'db.'))), 'No value moved while the web tier holds the placeholders.');

        $world->probe->answerFromNowOn($world->matches());

        $this->assertRolledBack($life->rollBack());
    }

    private function world(bool $usableFirstSlot = false): LifecycleWorld
    {
        $this->life = new LifecycleWorld($usableFirstSlot);
        $this->life->world->seedDefault();

        return $this->life;
    }

    private function assertRolledBack(RollBackResult $result): void
    {
        $life = $this->life ?? throw new \LogicException('No world.');
        self::assertSame(
            RollBackStatus::RolledBack,
            $result->status(),
            implode(' | ', array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals())),
        );
        self::assertSame(RunState::RolledBack, $life->run()->state());
        self::assertSame($life->world->ringBefore->fingerprint(), $life->world->config->keyRing()->fingerprint());
    }
}
