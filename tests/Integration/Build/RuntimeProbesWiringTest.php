<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\CompositeWorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\MagentoCliConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\PosixRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime\SleepingPause;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Security\PatternSecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\TransportWebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\BuiltInWebServer;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\MutableProbeContext;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The runtime adapters come out of the real container bound to their ports, with both probe transports
 * and every worker activity source collected, and work through the factories the build generates.
 */
final class RuntimeProbesWiringTest extends TestCase
{
    private const PASSWORD = 'wiring-db-password';

    private static ContainerInterface $container;

    private static string $buildDirectory;

    private ProbeStoreRoot $store;

    private string $cryptKey;

    private string $stateDirectory;

    public static function setUpBeforeClass(): void
    {
        self::$buildDirectory = TemporaryDirectory::create('key-rotator-runtime-wiring');
        $root = dirname(__DIR__, 3);
        self::$container = (new ContainerFactory(
            $root . '/tests/Fixtures/Container/runtime-probe-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile(self::$buildDirectory);
    }

    public static function tearDownAfterClass(): void
    {
        TemporaryDirectory::remove(self::$buildDirectory);
    }

    protected function setUp(): void
    {
        $this->cryptKey = KeyMaterial::rawKey() . "\n" . KeyMaterial::base64Key();
        $this->store = ProbeStoreRoot::create($this->cryptKey, self::PASSWORD);
        $this->stateDirectory = $this->store->path . '/var/encryption-key-rotation';
        $this->context()->use(
            new MagentoRoot($this->store->path),
            new ProbeSettings(null, null, null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false),
            $this->stateDirectory,
        );
    }

    protected function tearDown(): void
    {
        $this->store->remove();
    }

    public function testTheWebTierProbeReachesTheWebTierThroughTheHttpTransport(): void
    {
        $server = BuiltInWebServer::start($this->store->path . '/pub');
        try {
            $this->context()->useSettings(new ProbeSettings(null, $server->baseUrl(), null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false));

            $outcome = $this->probe()->observe(ProbeStoreRoot::ring($this->cryptKey));

            self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
        } finally {
            $server->stop();
        }
    }

    public function testTheWebTierProbeUsesTheFastCgiTransportForAPhpFpmAddress(): void
    {
        $this->context()->useSettings(new ProbeSettings('unix://' . $this->stateDirectory . '/none.sock', null, null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false));

        $outcome = $this->probe()->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('PHP-FPM at unix://' . $this->stateDirectory . '/none.sock could not be reached', $outcome->reason());
        self::assertDirectoryExists($this->stateDirectory . '/probe');
    }

    public function testTheWebTierProbeWithoutATransportIsUnreachable(): void
    {
        $outcome = $this->probe()->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('No probe transport configured', $outcome->reason());
    }

    public function testTheWorkerActivityCollectsEverySourceButItself(): void
    {
        $activity = $this->service(WorkerActivity::class);

        $descriptions = array_map(static fn(RunningProcess $p): string => $p->description(), $activity->running());

        self::assertInstanceOf(CompositeWorkerActivity::class, $activity);
        self::assertContains('a worker of the fixture source', $descriptions);
    }

    public function testTheConfigCacheCleanerRunsTheStoresCommand(): void
    {
        mkdir($this->store->path . '/bin');
        file_put_contents($this->store->path . '/bin/magento', "<?php\nexit(\$argv[1] === 'cache:clean' && \$argv[2] === 'config' ? 0 : 1);\n");
        $cleaner = $this->service(ConfigCacheCleaner::class);

        $outcome = $cleaner->clean();

        self::assertInstanceOf(MagentoCliConfigCacheCleaner::class, $cleaner);
        self::assertTrue($outcome->cleaned(), $outcome->reason());
    }

    public function testTheSecretRedactorReadsTheDatabasePasswordFromTheDeploymentConfig(): void
    {
        $redactor = $this->service(SecretRedactor::class);

        self::assertInstanceOf(PatternSecretRedactor::class, $redactor);
        self::assertSame('password [redacted]', $redactor->redact('password ' . self::PASSWORD));
    }

    public function testTheRuntimeUserIsTheEffectiveUser(): void
    {
        $user = $this->service(RuntimeUser::class);

        self::assertInstanceOf(PosixRuntimeUser::class, $user);
        $output = shell_exec('id -u');
        self::assertIsString($output);
        self::assertSame((int) trim($output), $user->effectiveUid());
    }

    public function testThePauseLetsTheSecondsPassForReal(): void
    {
        $pause = $this->service(Pause::class);
        self::assertInstanceOf(SleepingPause::class, $pause);

        $started = microtime(true);
        $pause->pause(1);

        self::assertGreaterThanOrEqual(0.9, microtime(true) - $started);
    }

    private function probe(): WebTierProbe
    {
        $probe = $this->service(WebTierProbe::class);
        self::assertInstanceOf(TransportWebTierProbe::class, $probe);

        return $probe;
    }

    private function context(): MutableProbeContext
    {
        return $this->service(MutableProbeContext::class);
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
        $service = self::$container->get('test.' . $id);
        self::assertInstanceOf($id, $service);

        return $service;
    }
}
