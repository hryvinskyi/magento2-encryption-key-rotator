<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\RunCommand;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The status names the run, where it stands, what it recorded, and what may run next.
 */
final class ReportStatusTest extends TestCase
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

    public function testWithoutARunOnlyAScanOrANewRotationIsOffered(): void
    {
        $report = $this->world->status->status();

        self::assertFalse($report->hasRun());
        self::assertFalse($report->isActive());
        self::assertNull($report->state());
        self::assertSame([], $report->history());
        self::assertSame([RunCommand::Scan, RunCommand::Rotate], $report->nextCommands());
    }

    public function testAWaitingRunIsReportedWithItsHistory(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $result = $world->rotate();

        $report = $world->status->status();

        self::assertSame($result->runId()?->toString(), $report->runId());
        self::assertTrue($report->isActive());
        self::assertSame(RunState::KeyAdded, $report->state());
        self::assertSame(['started', 'key_pending', 'key_added'], array_map(static fn(array $e): string => $e['state']->value, $report->history()));
        self::assertSame($world->ringBefore->fingerprint(), $report->ringFingerprintBefore());
        self::assertSame($world->config->keyRing()->fingerprint(), $report->ringFingerprint());
        self::assertSame([1, 2], $report->sourceIndices());
        self::assertSame(3, $report->newIndex());
        self::assertNotNull($report->lastRingWriteAt());
        self::assertNull($report->lastSummary());
        self::assertSame([RunCommand::Rotate, RunCommand::Rollback], $report->nextCommands());
    }

    public function testAReencryptedRunReportsItsLastSummary(): void
    {
        $this->world->rotate();

        $report = $this->world->status->status();

        self::assertSame(RunState::Reencrypted, $report->state());
        self::assertSame([1 => 1, 3 => 8], $report->lastSummary()?->verifiedPerIndex());
        self::assertTrue($report->configCacheCleaned());
        self::assertFalse($report->probeSkipped());
        self::assertSame([RunCommand::Rotate, RunCommand::Retire, RunCommand::Rollback], $report->nextCommands());
    }

    public function testTheReportNamesTheRingEnvPhpHoldsNow(): void
    {
        $this->world->rotate();

        $report = $this->world->status->status();

        self::assertSame($this->world->config->keyRing()->fingerprint(), $report->deploymentRingFingerprint());
        self::assertFalse($report->deploymentRingDiffers());
    }

    public function testADeployThatPutsBackTheEnvPhpFromBeforeTheRunIsReported(): void
    {
        $world = $this->world;
        $world->rotate();

        $world->config->replaceRing($world->ringBefore);
        $report = $world->status->status();

        self::assertSame($world->ringBefore->fingerprint(), $report->deploymentRingFingerprint());
        self::assertTrue($report->deploymentRingDiffers());
    }

    public function testWithoutARunTheRingOfEnvPhpIsReportedAndNothingDiffers(): void
    {
        $report = $this->world->status->status();

        self::assertSame($this->world->ringBefore->fingerprint(), $report->deploymentRingFingerprint());
        self::assertFalse($report->deploymentRingDiffers());
    }

    public function testARollingBackRunOffersOnlyTheRollback(): void
    {
        $world = $this->world;
        $world->probe->enqueue($world->matches());
        $world->probe->answerFromNowOn($world->differs());
        $run = $world->runs->get($world->rotate()->runId() ?? throw new \LogicException('No run.'));
        $run->rollingBack($world->clock->now());
        $world->runs->save($run);

        $report = $world->status->status();

        self::assertSame(RunState::RollingBack, $report->state());
        self::assertSame(RunState::KeyAdded, $report->rolledBackFrom());
        self::assertSame([RunCommand::Rollback], $report->nextCommands());
    }

    public function testTheLatestFinishedRunIsReportedWhenNoneIsActive(): void
    {
        $world = $this->world;
        $world->runs->afterSave(static function (): never {
            throw new \RuntimeException('crash after the run started');
        });
        try {
            $world->rotate($world->request(probeSettings: $world->probeSettings(skipped: true)));
        } catch (\RuntimeException) {
            $world->runs->afterSave(null);
        }
        $run = $world->runs->latest() ?? throw new \LogicException('No run.');
        $run->rollingBack($world->clock->now());
        $run->rolledBack($run->ringFingerprintBefore(), $world->clock->now());
        $world->runs->save($run);

        $report = $world->status->status();

        self::assertTrue($report->hasRun());
        self::assertFalse($report->isActive());
        self::assertSame(RunState::RolledBack, $report->state());
        self::assertSame([RunCommand::Purge, RunCommand::Rotate], $report->nextCommands());
    }

    /**
     * @return iterable<string, array{RunState, list<RunCommand>}>
     */
    public static function nextCommands(): iterable
    {
        yield 'started' => [RunState::Started, [RunCommand::Rotate, RunCommand::Rollback]];
        yield 'key_pending' => [RunState::KeyPending, [RunCommand::Rotate, RunCommand::Rollback]];
        yield 'key_added' => [RunState::KeyAdded, [RunCommand::Rotate, RunCommand::Rollback]];
        yield 'web_confirmed' => [RunState::WebConfirmed, [RunCommand::Rotate, RunCommand::Rollback]];
        yield 'reencrypted' => [RunState::Reencrypted, [RunCommand::Rotate, RunCommand::Retire, RunCommand::Rollback]];
        yield 'retire_pending' => [RunState::RetirePending, [RunCommand::Retire, RunCommand::Rollback]];
        yield 'retired' => [RunState::Retired, [RunCommand::Purge, RunCommand::Rollback]];
        yield 'rolling_back' => [RunState::RollingBack, [RunCommand::Rollback]];
        yield 'rolled_back' => [RunState::RolledBack, [RunCommand::Purge, RunCommand::Rotate]];
        yield 'purged' => [RunState::Purged, [RunCommand::Scan, RunCommand::Rotate]];
    }

    /**
     * @param list<RunCommand> $expected
     */
    #[DataProvider('nextCommands')]
    public function testEveryStateAllowsItsNextCommands(RunState $state, array $expected): void
    {
        self::assertSame($expected, RunCommand::allowedAfter($state));
    }
}
