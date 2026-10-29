<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\RunPreflight;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StateDirectoryPlacement;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPreflightResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * The checks before a write: each failing one is a refusal of its own, all are reported at once, and an
 * override that waived one is listed for the run to record.
 */
final class RunPreflightTest extends TestCase
{
    private RotationWorld $world;

    /**
     * @var list<string>
     */
    private array $directories = [];

    protected function setUp(): void
    {
        $this->world = new RotationWorld();
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
        foreach ($this->directories as $directory) {
            TemporaryDirectory::remove($directory);
        }
    }

    public function testAStoreAsExpectedPasses(): void
    {
        $result = $this->check($this->world->ringBefore->fingerprint(), $this->world->clock->now());

        self::assertTrue($result->passed());
        self::assertSame([], $result->workers());
        self::assertSame([], $result->waived());
    }

    public function testEveryFailingCheckIsADistinctReasonReportedAtOnce(): void
    {
        $this->world->cleanUp();
        $this->world = new RotationWorld(runtimeUid: 0);
        $world = $this->world;
        $world->config->holdNonLiteralData();
        $world->workers->start('bin/magento cron:run', null);

        $result = $this->check(str_repeat('0', 16), $world->clock->now());

        self::assertFalse($result->passed());
        self::assertSame(
            [RefusalReason::RingChanged, RefusalReason::DeploymentConfigNotLiteral, RefusalReason::OtherUser, RefusalReason::WorkersRunning],
            $this->reasons($result),
        );
        self::assertStringContainsString($world->ringBefore->fingerprint(), $result->refusals()[0]->message());
        self::assertStringContainsString(str_repeat('0', 16), $result->refusals()[0]->message());
        self::assertStringContainsString('bin/magento cron:run', $result->refusals()[3]->message());
    }

    public function testADeploymentConfigThatCannotBeReplacedIsADistinctRefusal(): void
    {
        $this->world->config->makeUnwritable();

        $result = $this->check($this->world->ringBefore->fingerprint(), null);

        self::assertFalse($result->passed());
        self::assertSame([RefusalReason::DeploymentConfigNotWritable], $this->reasons($result));
        self::assertStringContainsString('not writable', $result->refusals()[0]->message());
    }

    public function testARingThatCannotBeReadAsUsableKeysIsRefused(): void
    {
        $world = $this->world;
        $reader = new class ($world->config) implements DeploymentConfigReader {
            public function __construct(
                private readonly DeploymentConfigReader $inner,
            ) {}

            public function keyRing(): KeyRing
            {
                throw new InvalidKey('Key slot 1 does not hold a usable key: An encryption key cannot contain whitespace.');
            }

            public function databaseSettings(): DatabaseSettings
            {
                return $this->inner->databaseSettings();
            }

            public function systemValues(): array
            {
                return $this->inner->systemValues();
            }

            public function committedSystemValues(): array
            {
                return $this->inner->committedSystemValues();
            }

            public function ownerUid(): int
            {
                return $this->inner->ownerUid();
            }

            public function holdsOnlyLiteralData(): bool
            {
                return $this->inner->holdsOnlyLiteralData();
            }

            public function isWritable(): bool
            {
                return $this->inner->isWritable();
            }

            public function secretStrings(): array
            {
                return $this->inner->secretStrings();
            }
        };
        $refusals = new DirectRefusalFactory();
        $preflight = new RunPreflight(
            $reader,
            new FixedRuntimeUser(RotationWorld::OWNER_UID),
            new FixedMagentoRoot(new MagentoRoot($world->root)),
            new FixedStateDirectory($world->stateDirectory),
            new StateDirectoryPlacement($refusals),
            $world->workers,
            $refusals,
            new DirectPreflightResultFactory(),
        );

        $result = $preflight->check(null, null, false, false, $world->probeSettings());

        self::assertSame([RefusalReason::RingUnusable], $this->reasons($result));
        self::assertStringContainsString('Key slot 1', $result->refusals()[0]->message());
    }

    public function testOnlyProcessesOlderThanTheRingWriteBlockAndAnUnknownStartCountsAsOlder(): void
    {
        $world = $this->world;
        $written = $world->clock->now();
        $world->workers->start('started before', $written->modify('-1 second'));
        $world->workers->start('start unknown', null);
        $world->workers->start('started at the write', $written);
        $world->workers->start('started after', $written->modify('+1 second'));

        $result = $this->check(null, $written);

        self::assertSame([RefusalReason::WorkersRunning], $this->reasons($result));
        self::assertSame(['started before', 'start unknown'], array_map(static fn(RunningProcess $p): string => $p->description(), $result->workers()));
    }

    public function testWorkersAreLeftUncheckedWithoutARingWrite(): void
    {
        $this->world->workers->start('bin/magento cron:run', null);

        self::assertTrue($this->check(null, null)->passed());
    }

    public function testOverridesThatWaivedACheckAreListed(): void
    {
        $this->world->cleanUp();
        $this->world = new RotationWorld(runtimeUid: 0);
        $this->world->workers->start('bin/magento cron:run', null);

        $result = $this->world->preflight->check(null, $this->world->clock->now(), true, true, $this->world->probeSettings());

        self::assertTrue($result->passed());
        self::assertSame([RunOverride::AllowOtherUser, RunOverride::IgnoreWorkers], $result->waived());
        self::assertCount(1, $result->workers());
    }

    public function testOverridesThatWaiveNothingAreNotListed(): void
    {
        $result = $this->world->preflight->check(null, $this->world->clock->now(), true, true, $this->world->probeSettings());

        self::assertSame([], $result->waived());
    }

    public function testTheDefaultStateDirectoryOutsideTheDocumentRootIsAccepted(): void
    {
        $root = $this->magentoRoot();

        self::assertNull($this->placement()->refusal(new MagentoRoot($root), $root . '/var/encryption-key-rotation', 'pub'));
    }

    public function testAStateDirectoryInsideTheDocumentRootIsRefused(): void
    {
        $root = new MagentoRoot($this->magentoRoot());

        $insidePub = $this->placement()->refusal($root, $root->path() . '/pub/media/rotation', 'pub');
        $rootServed = $this->placement()->refusal($root, $root->path() . '/var/encryption-key-rotation', '.');

        self::assertSame(RefusalReason::StateDirectoryInDocroot, $insidePub?->reason());
        self::assertSame(RefusalReason::StateDirectoryInDocroot, $rootServed?->reason());
    }

    public function testAStateDirectoryReachedThroughALinkIntoTheDocumentRootIsRefused(): void
    {
        $root = $this->magentoRoot();
        $outside = $this->directory();
        symlink($root . '/pub', $outside . '/served');

        $refusal = $this->placement()->refusal(new MagentoRoot($root), $outside . '/served/rotation', 'pub');

        self::assertSame(RefusalReason::StateDirectoryInDocroot, $refusal?->reason());
    }

    public function testAReleaseRootReachedThroughALinkNeedsAStateDirectoryOutsideTheRelease(): void
    {
        $base = $this->directory();
        mkdir($base . '/releases/7/app/etc', 0700, true);
        mkdir($base . '/releases/7/pub', 0700, true);
        touch($base . '/releases/7/' . MagentoRoot::DEPLOYMENT_CONFIG);
        mkdir($base . '/shared', 0700, true);
        symlink($base . '/releases/7', $base . '/current');
        $root = new MagentoRoot($base . '/current');

        $default = $this->placement()->refusal($root, $base . '/current/var/encryption-key-rotation', 'pub');
        $inRelease = $this->placement()->refusal($root, $base . '/releases/7/var/rotation', 'pub');
        $shared = $this->placement()->refusal($root, $base . '/shared/encryption-key-rotation', 'pub');

        self::assertSame(RefusalReason::StateDirectoryInRelease, $default?->reason());
        self::assertStringContainsString($base . '/releases/7', $default->message());
        self::assertSame(RefusalReason::StateDirectoryInRelease, $inRelease?->reason());
        self::assertNull($shared);
    }

    public function testTheStateDirectoryCheckRunsWithThePreflight(): void
    {
        $result = $this->world->preflight->check(
            null,
            null,
            false,
            false,
            new ProbeSettings('unix:///run/php-fpm.sock', null, null, '.', true, 0, false),
        );

        self::assertSame([RefusalReason::StateDirectoryInDocroot], $this->reasons($result));
    }

    private function check(?string $expected, ?\DateTimeImmutable $ringWrittenAt): PreflightResult
    {
        return $this->world->preflight->check($expected, $ringWrittenAt, false, false, $this->world->probeSettings());
    }

    /**
     * @return list<RefusalReason>
     */
    private function reasons(PreflightResult $result): array
    {
        return array_map(static fn(Refusal $refusal): RefusalReason => $refusal->reason(), $result->refusals());
    }

    private function placement(): StateDirectoryPlacement
    {
        return new StateDirectoryPlacement(new DirectRefusalFactory());
    }

    private function magentoRoot(): string
    {
        $root = $this->directory();
        mkdir($root . '/app/etc', 0700, true);
        mkdir($root . '/pub', 0700, true);
        touch($root . '/' . MagentoRoot::DEPLOYMENT_CONFIG);

        return $root;
    }

    private function directory(): string
    {
        $directory = TemporaryDirectory::create('key-rotator-preflight');
        $this->directories[] = $directory;

        return $directory;
    }
}
