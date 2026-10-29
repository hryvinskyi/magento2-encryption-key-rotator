<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireOldKeys;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Psr\Container\ContainerInterface;

/**
 * The retirement, rollback and purge use cases resolve from the real container with every collaborator
 * autowired, and the generated factories of the values they exchange build those values.
 */
final class RetireRollbackPurgeWiringTest extends TestCase
{
    private static ?ContainerInterface $container = null;
    private static string $buildDirectory = '';

    public static function setUpBeforeClass(): void
    {
        self::$buildDirectory = TemporaryDirectory::create('key-rotator-retire-rollback-purge');
        $root = dirname(__DIR__, 3);
        self::$container = (new ContainerFactory(
            $root . '/tests/Fixtures/Container/retire-rollback-purge-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile(self::$buildDirectory);
    }

    public static function tearDownAfterClass(): void
    {
        self::$container = null;
        TemporaryDirectory::remove(self::$buildDirectory);
    }

    public function testTheUseCasesResolveFromTheContainerOncePerContainer(): void
    {
        self::assertSame($this->service(RetireOldKeys::class), $this->service(RetireOldKeys::class));
        self::assertSame($this->service(RollBackRotation::class), $this->service(RollBackRotation::class));
        self::assertSame($this->service(PurgeRotation::class), $this->service(PurgeRotation::class));
    }

    public function testTheGeneratedFactoriesBuildTheRequestsAndResults(): void
    {
        $probe = $this->service(ProbeSettingsFactory::class)->create('unix:///run/php-fpm.sock', null, null, ProbeSettings::DEFAULT_DOCROOT, true, 30, false);
        $runId = $this->service(RunIdFactory::class)->create(str_repeat('ab', 16));

        $retire = $this->service(RetireRequestFactory::class)->create(true, false, true, false, $probe);
        self::assertTrue($retire->acceptsEmbedded());
        self::assertFalse($retire->cacheCleanedManually());
        self::assertTrue($retire->ignoresWorkers());
        self::assertSame($probe, $retire->probeSettings());

        $rollBack = $this->service(RollBackRequestFactory::class)->create(false, true, $probe, true);
        self::assertTrue($rollBack->allowsOtherUser());
        self::assertTrue($rollBack->acceptsEmbedded());

        $purge = $this->service(PurgeRequestFactory::class)->create($runId, true);
        self::assertSame($runId, $purge->runId());
        self::assertTrue($purge->acceptsLoss());

        $retired = $this->service(RetireResultFactory::class)->stopped(RetireStatus::Refused, $runId, RunState::Reencrypted, [], [], null, null, '00000000000000aa');
        self::assertSame(RetireStatus::Refused, $retired->status());
        self::assertSame('00000000000000aa', $retired->ringFingerprint());

        $rolledBack = $this->service(RollBackResultFactory::class)->stopped(RollBackStatus::AlreadyRolledBack, $runId, RunState::RolledBack, RunState::Reencrypted, [], [], null, null);
        self::assertSame(RunState::Reencrypted, $rolledBack->rolledBackFrom());

        $purged = $this->service(PurgeResultFactory::class)->stopped(PurgeStatus::NothingToPurge, $runId, null, [], null, [], 0, 0, 0, 2);
        self::assertSame(PurgeStatus::NothingToPurge, $purged->status());
        self::assertSame(2, $purged->withoutRowKey());

        $journal = $this->service(JournalReversalOutcomeFactory::class)->create(3, 1, []);
        self::assertSame(3, $journal->reverted());
        self::assertSame(1, $journal->superseded());
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    private function service(string $id): object
    {
        $container = self::$container ?? throw new \LogicException('The container is not compiled.');
        $service = $container->get('test.' . $id);
        if (!$service instanceof $id) {
            throw new \LogicException(sprintf('The container holds no %s.', $id));
        }

        return $service;
    }
}
