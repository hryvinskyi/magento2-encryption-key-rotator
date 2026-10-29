<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\LifecycleWorld;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * A retirement interrupted at any point is resumed by running it again: it reads the deployment
 * configuration as it is, writes the placeholders it kept and never new ones, and ends at `retired`.
 */
final class RetireOldKeysResumeTest extends TestCase
{
    private LifecycleWorld $life;

    protected function setUp(): void
    {
        $this->life = new LifecycleWorld();
        $this->life->world->seedDefault();
        $this->life->rotate();
        $this->life->deployCommittedUnderNewKey();
    }

    protected function tearDown(): void
    {
        $this->life->cleanUp();
    }

    public function testACrashAfterRetirePendingIsSavedButBeforeTheWriteIsResumedWithTheKeptPlaceholders(): void
    {
        $life = $this->life;
        $world = $life->world;
        $ringBeforeRetire = $world->config->keyRing()->fingerprint();
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::RetirePending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after retire_pending');
            }
        });

        $this->crash('crash after retire_pending');

        self::assertSame(RunState::RetirePending, $life->run()->state());
        self::assertSame($ringBeforeRetire, $world->config->keyRing()->fingerprint(), 'The ring was not written.');
        $kept = $this->placeholders($world->runs->keptPlaceholders($life->runId()));
        self::assertCount(2, $kept);

        $result = $life->retire();

        $this->assertRetiredWith($result, $kept);
        self::assertSame(1, $this->placeholderRingWrites(), 'The placeholder ring is written once.');
    }

    public function testAResumedRetirementRefusesItsRingWriteWhileTheCommittedConfigurationHoldsAValueOnAMovedIndex(): void
    {
        $life = $this->life;
        $world = $life->world;
        $ringBeforeRetire = $world->config->keyRing()->fingerprint();
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::RetirePending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after retire_pending');
            }
        });
        $this->crash('crash after retire_pending');
        $life->deployCommittedUnderOldKey();

        $refused = $life->retire();

        self::assertSame(RetireStatus::Refused, $refused->status());
        self::assertSame([RefusalReason::RetireBlocked], array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $refused->refusals()));
        self::assertStringContainsString(implode('/', RotationWorld::COMMITTED_PATH), $refused->refusals()[0]->message());
        self::assertSame($ringBeforeRetire, $world->config->keyRing()->fingerprint(), 'The placeholders were not written.');
        self::assertSame(RunState::RetirePending, $life->run()->state());

        $life->deployCommittedUnderNewKey();

        $this->assertRetiredWith($life->retire(), $this->placeholders($world->runs->keptPlaceholders($life->runId())));
    }

    public function testACrashAfterTheWriteButBeforeRetiredIsSavedContinuesAtTheProbe(): void
    {
        $life = $this->life;
        $world = $life->world;
        $world->config->afterWrite(function (KeyRing $ring) use ($world): void {
            if ($ring->slot(1)?->isRetired() === true) {
                $world->config->afterWrite(null);

                throw new \RuntimeException('crash after the placeholder write');
            }
        });

        $this->crash('crash after the placeholder write');

        $run = $life->run();
        self::assertSame(RunState::RetirePending, $run->state());
        self::assertSame($run->intendedRingFingerprint(), $world->config->keyRing()->fingerprint(), 'The announced ring is in place.');
        $kept = $this->placeholders($world->runs->keptPlaceholders($life->runId()));
        $probesBefore = count($world->probe->observed());

        $result = $life->retire();

        $this->assertRetiredWith($result, $kept);
        self::assertSame(1, $this->placeholderRingWrites(), 'The write found in place is not made again.');
        self::assertSame($world->config->keyRing()->fingerprint(), $world->probe->observed()[$probesBefore] ?? null, 'The resumed retirement asks the web tier first.');
    }

    public function testARetirementTheWebTierDidNotConfirmWaitsAndIsResumedByRunningItAgain(): void
    {
        $life = $this->life;
        $world = $life->world;
        $world->probe->answerFromNowOn($world->differs());

        $waiting = $life->retire($life->retireRequest(probeSettings: $world->probeSettings(waitSeconds: 10)));

        self::assertSame(RetireStatus::AwaitingWebTier, $waiting->status());
        self::assertSame(RunState::RetirePending, $life->run()->state());
        self::assertGreaterThan(1, count($world->probe->observed()), 'The web tier is asked again until the wait is spent.');
        $kept = $this->placeholders($world->runs->keptPlaceholders($life->runId()));

        $world->probe->answerFromNowOn($world->matches());
        $result = $life->retire();

        $this->assertRetiredWith($result, $kept);
        self::assertSame(1, $this->placeholderRingWrites());
    }

    public function testARetirePendingRunWhoseRingSomeoneElseChangedIsRefusedNamingEveryFingerprint(): void
    {
        $life = $this->life;
        $world = $life->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::RetirePending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after retire_pending');
            }
        });
        $this->crash('crash after retire_pending');
        $world->config->replaceRing($world->ringBefore);

        $result = $life->retire();

        self::assertSame(RetireStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RingChanged], array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $result->refusals()));
        $message = $result->refusals()[0]->message();
        $run = $life->run();
        self::assertStringContainsString($world->ringBefore->fingerprint(), $message);
        self::assertStringContainsString($run->ringFingerprint(), $message);
        self::assertStringContainsString((string) $run->intendedRingFingerprint(), $message);
        self::assertSame($world->ringBefore->fingerprint(), $world->config->keyRing()->fingerprint(), 'Nothing was written.');
    }

    /**
     * @param array<int, string> $kept index => kept placeholder
     */
    private function assertRetiredWith(RetireResult $result, array $kept): void
    {
        $life = $this->life;
        self::assertSame(RetireStatus::Retired, $result->status(), implode(' | ', array_map(static fn(Refusal $refusal): string => $refusal->message(), $result->refusals())));
        self::assertSame(RunState::Retired, $life->run()->state());
        $ring = $life->world->config->keyRing();
        foreach ($kept as $index => $placeholder) {
            self::assertSame($placeholder, $ring->slot($index)?->raw(), sprintf('Slot %d holds the kept placeholder.', $index));
        }
        self::assertSame($kept, $this->placeholders($life->world->runs->keptPlaceholders($life->runId())), 'No other placeholders were kept.');
    }

    /**
     * @param list<KeySlot> $slots
     *
     * @return array<int, string>
     */
    private function placeholders(array $slots): array
    {
        $entries = [];
        foreach ($slots as $slot) {
            $entries[$slot->index()] = $slot->raw();
        }

        return $entries;
    }

    /**
     * How many writes of the deployment configuration changed the key ring into one with placeholders in
     * the moved slots.
     */
    private function placeholderRingWrites(): int
    {
        return count(array_filter(
            $this->life->world->config->writes(),
            static fn(array $write): bool => $write['ring']->slot(1)?->isRetired() === true
                && $write['expected'] !== $write['ring']->fingerprint(),
        ));
    }

    private function crash(string $message): void
    {
        try {
            $this->life->retire();
            self::fail('The retirement was expected to crash.');
        } catch (\RuntimeException $crash) {
            self::assertSame($message, $crash->getMessage());
        } finally {
            $this->life->world->runs->unlock();
        }
    }
}
