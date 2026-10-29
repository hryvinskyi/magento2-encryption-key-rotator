<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RunDirectoryLayout;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\StateDirectoryTrust;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgiProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeInterruptGuard;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\TransportWebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectFastCgiClientFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectGetRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectNetworkSocketFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectUnixDomainSocketFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedRuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\FastCgiServer;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

/**
 * The probe runs inside a real PHP-FPM pool, straight over its socket: it sees the key ring the pool
 * sees, opcode cache included, and its file never outlives a probe.
 */
final class FastCgiProbeTransportTest extends TestCase
{
    private ProbeStoreRoot $store;

    private string $cryptKey;

    private string $stateDirectory;

    private ?FastCgiServer $fpm = null;

    private RecordingProgress $progress;

    protected function setUp(): void
    {
        $this->cryptKey = KeyMaterial::rawKey() . ' ' . KeyMaterial::base64Key();
        $this->store = ProbeStoreRoot::create($this->cryptKey);
        $this->stateDirectory = TemporaryDirectory::create('key-rotator-state');
        $this->progress = new RecordingProgress();
    }

    protected function tearDown(): void
    {
        $this->fpm?->stop();
        $this->store->remove();
        TemporaryDirectory::remove($this->stateDirectory);
    }

    public function testThePoolHoldingTheRingOnDiskMatches(): void
    {
        $this->fpm = FastCgiServer::start();

        $outcome = $this->probe($this->fpm->address())->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
        $this->assertProbeDirectoryIsClean();
    }

    public function testThePoolKeepsTheRingItCachedAfterTheFileChanged(): void
    {
        $this->fpm = FastCgiServer::start();
        $probe = $this->probe($this->fpm->address());
        $before = ProbeStoreRoot::ring($this->cryptKey);
        self::assertSame(ProbeStatus::Matches, $probe->observe($before)->status());

        $rotated = $this->cryptKey . "\n" . KeyMaterial::base64Key();
        $this->store->writeDeploymentConfig($rotated);
        $outcome = $probe->observe(ProbeStoreRoot::ring($rotated));

        self::assertSame(ProbeStatus::Differs, $outcome->status(), $outcome->reason());
        self::assertStringContainsString('reload PHP-FPM or reset opcache', $outcome->reason());
        self::assertSame(ProbeStatus::Matches, $probe->observe($before)->status(), 'the pool still serves the cached ring');
        $this->assertProbeDirectoryIsClean();
    }

    public function testAWrongSocketPathIsUnreachable(): void
    {
        $outcome = $this->probe('unix://' . $this->stateDirectory . '/no-such.sock')->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('could not be reached', $outcome->reason());
        $this->assertProbeDirectoryIsClean();
    }

    public function testAServerThatNeverAnswersTimesOutAndTheFileIsStillDeleted(): void
    {
        $silent = TemporaryDirectory::create('key-rotator-silent');
        $socket = $silent . '/silent.sock';
        $server = new Process([PHP_BINARY, '-r', sprintf(
            '$s = stream_socket_server(%s); $held = []; while ($c = @stream_socket_accept($s, 30)) { $held[] = $c; }',
            var_export('unix://' . $socket, true),
        )]);
        $server->start();
        try {
            for ($attempt = 0; $attempt < 100 && !file_exists($socket); $attempt++) {
                usleep(50_000);
            }

            $outcome = $this->probe('unix://' . $socket, 1000)->observe(ProbeStoreRoot::ring($this->cryptKey));

            self::assertSame(ProbeStatus::Unreachable, $outcome->status());
            self::assertStringContainsString('did not answer the probe within 1 s', $outcome->reason());
            $this->assertProbeDirectoryIsClean();
        } finally {
            $server->stop(1);
            // A socket file is no regular file: it is removed here, before the directory.
            @unlink($socket);
            TemporaryDirectory::remove($silent);
        }
    }

    public function testAPoolThatMayNotReadTheProbeDirectoryRefusesWithItsStatusLine(): void
    {
        $this->fpm = FastCgiServer::start(['php_admin_value[open_basedir] = ' . $this->store->path]);

        $outcome = $this->probe($this->fpm->address())->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertMatchesRegularExpression('/refused the probe script with "(403|404)[^"]*"/', $outcome->reason());
        self::assertStringContainsString('open_basedir', $outcome->reason());
        $this->assertProbeDirectoryIsClean();
    }

    public function testAProbeDirectoryThatIsASymbolicLinkIsRefusedAndNothingIsWrittenWhereItPoints(): void
    {
        $victim = TemporaryDirectory::create('key-rotator-probe-victim');
        symlink($victim, $this->stateDirectory . '/' . FastCgiProbeTransport::DIRECTORY);

        try {
            $this->probe('unix://' . $this->stateDirectory . '/no-such.sock')->observe(ProbeStoreRoot::ring($this->cryptKey));
            self::fail('The probe wrote through a symbolic link.');
        } catch (UntrustedStateDirectory $refused) {
            self::assertStringContainsString('is a symbolic link', $refused->getMessage());
        } finally {
            self::assertSame(['.', '..'], scandir($victim));
            TemporaryDirectory::remove($victim);
        }
    }

    public function testAProbeFileAKilledProbeLeftIsDeletedByTheNextProbe(): void
    {
        $this->fpm = FastCgiServer::start();
        $directory = $this->stateDirectory . '/' . FastCgiProbeTransport::DIRECTORY;
        mkdir($directory, 0711);
        $stale = $directory . '/key-rotator-probe-' . str_repeat('5a', 16) . '.php';
        file_put_contents($stale, '<?php echo "stale";');

        $outcome = $this->probe($this->fpm->address())->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
        $this->assertProbeDirectoryIsClean();
    }

    private function probe(string $address, int $readTimeoutMs = FastCgiProbeTransport::READ_TIMEOUT_MS): TransportWebTierProbe
    {
        $transport = new FastCgiProbeTransport(
            new RunDirectoryLayout(
                new FixedStateDirectory($this->stateDirectory),
                new StateDirectoryTrust(new FixedRuntimeUser(posix_geteuid())),
                new FileOperations(),
            ),
            new DirectUnixDomainSocketFactory(),
            new DirectNetworkSocketFactory(),
            new DirectGetRequestFactory(),
            new DirectFastCgiClientFactory(),
            FastCgiProbeTransport::CONNECT_TIMEOUT_MS,
            $readTimeoutMs,
        );

        return new TransportWebTierProbe(
            [$transport],
            new FixedProbeSettings(new ProbeSettings($address, null, null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false)),
            new FixedMagentoRoot(new MagentoRoot($this->store->path)),
            new ProbeScriptRenderer(),
            new ProbeScriptWriter(),
            new ProbeInterruptGuard(new ProbeScriptWriter()),
            new DirectProbeOutcomeFactory(),
            $this->progress,
        );
    }

    private function assertProbeDirectoryIsClean(): void
    {
        $directory = $this->stateDirectory . '/' . FastCgiProbeTransport::DIRECTORY;
        clearstatcache();
        self::assertDirectoryExists($directory);
        self::assertSame(FastCgiProbeTransport::DIRECTORY_MODE, fileperms($directory) & 0777);
        self::assertSame(['.', '..'], scandir($directory));
        self::assertSame([], $this->progress->warnings());
    }
}
