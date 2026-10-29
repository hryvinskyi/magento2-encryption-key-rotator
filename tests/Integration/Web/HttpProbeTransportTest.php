<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\HttpProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeHostPolicy;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeInterruptGuard;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\TransportWebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\BuiltInWebServer;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\HttpClient;

/**
 * The probe runs through a web server that executes any `.php` file in the document root: it sees the
 * ring on disk, answers nobody without its token, and refuses to go to a public host.
 */
final class HttpProbeTransportTest extends TestCase
{
    private ProbeStoreRoot $store;

    private string $cryptKey;

    private BuiltInWebServer $server;

    private RecordingProgress $progress;

    protected function setUp(): void
    {
        $this->cryptKey = KeyMaterial::rawKey() . "\n" . KeyMaterial::base64Key();
        $this->store = ProbeStoreRoot::create($this->cryptKey);
        $this->server = BuiltInWebServer::start($this->store->path . '/pub');
        $this->progress = new RecordingProgress();
    }

    protected function tearDown(): void
    {
        $this->server->stop();
        $this->store->remove();
    }

    public function testAWebTierHoldingTheRingOnDiskMatches(): void
    {
        $outcome = $this->probe($this->server->baseUrl())->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
        $this->assertNoProbeFileIn('pub');
    }

    public function testAProbeFileAKilledProbeLeftInTheDocumentRootIsDeletedByTheNextProbe(): void
    {
        $stale = $this->store->path . '/pub/key-rotator-probe-' . str_repeat('5a', 16) . '.php';
        file_put_contents($stale, '<?php echo "stale";');
        file_put_contents($this->store->path . '/pub/.key-rotator-probe-' . str_repeat('6b', 16) . '.php.tmp', '<?php');

        $outcome = $this->probe($this->server->baseUrl())->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
        $this->assertNoProbeFileIn('pub');
    }

    public function testAProxyTheEnvironmentNamesNeverCarriesTheProbe(): void
    {
        $saved = [];
        foreach (['http_proxy', 'HTTP_PROXY', 'https_proxy', 'HTTPS_PROXY', 'all_proxy', 'ALL_PROXY'] as $name) {
            $saved[$name] = $_SERVER[$name] ?? null;
            $_SERVER[$name] = 'http://127.0.0.1:9';
        }

        try {
            $outcome = $this->probe($this->server->baseUrl())->observe(ProbeStoreRoot::ring($this->cryptKey));
        } finally {
            foreach ($saved as $name => $value) {
                if ($value === null) {
                    unset($_SERVER[$name]);
                } else {
                    $_SERVER[$name] = $value;
                }
            }
        }

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
    }

    public function testAHostHeaderOverPlainHttpStillReachesTheProbe(): void
    {
        $outcome = $this->probe($this->server->baseUrl(), hostHeader: 'store.test')->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Matches, $outcome->status(), $outcome->reason());
    }

    public function testADeploymentConfigEditedAfterTheExpectedRingWasTakenDiffers(): void
    {
        $expected = ProbeStoreRoot::ring($this->cryptKey);
        $this->store->writeDeploymentConfig($this->cryptKey . "\n" . KeyMaterial::base64Key());

        $outcome = $this->probe($this->server->baseUrl())->observe($expected);

        self::assertSame(ProbeStatus::Differs, $outcome->status(), $outcome->reason());
        $this->assertNoProbeFileIn('pub');
    }

    public function testAWrongDocumentRootIsUnreachableAndPointsAtTheFastCgiTransport(): void
    {
        $outcome = $this->probe($this->server->baseUrl(), 'var')->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('HTTP 404', $outcome->reason());
        self::assertStringContainsString('--probe-fcgi', $outcome->reason());
        $this->assertNoProbeFileIn('var');
    }

    public function testTheProbeFileAnswersNobodyWithoutItsToken(): void
    {
        $token = bin2hex(random_bytes(32));
        $writer = new ProbeScriptWriter();
        $path = $this->store->path . '/pub/' . $writer->newFileName();
        $writer->write($path, (new ProbeScriptRenderer())->render($this->store->deploymentConfigFile(), $token));
        $http = HttpClient::create();
        $url = $this->server->baseUrl() . '/' . basename($path);

        try {
            $withoutToken = $http->request('GET', $url);
            $wrongToken = $http->request('GET', $url . '?t=' . bin2hex(random_bytes(32)));
            $withToken = $http->request('GET', $url . '?t=' . $token);

            self::assertSame(404, $withoutToken->getStatusCode());
            self::assertSame('', $withoutToken->getContent(false));
            self::assertSame(404, $wrongToken->getStatusCode());
            self::assertSame('', $wrongToken->getContent(false));
            self::assertSame(200, $withToken->getStatusCode());
            self::assertSame(['no-store'], $withToken->getHeaders()['cache-control'] ?? []);
            self::assertSame(
                hash_hmac('sha256', ProbeStoreRoot::ring($this->cryptKey)->export(), $token),
                $withToken->getContent(),
            );
        } finally {
            self::assertTrue($writer->remove($path));
        }
    }

    public function testAPublicBaseUrlHostIsRefused(): void
    {
        $outcome = $this->probe('https://shop.example.com')->observe(ProbeStoreRoot::ring($this->cryptKey));

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('public host shop.example.com', $outcome->reason());
        $this->assertNoProbeFileIn('pub');
    }

    private function probe(string $baseUrl, string $docroot = ProbeSettings::DEFAULT_DOCROOT, ?string $hostHeader = null): TransportWebTierProbe
    {
        return new TransportWebTierProbe(
            [new HttpProbeTransport(new FixedMagentoRoot(new MagentoRoot($this->store->path)), HttpClient::create(), new ProbeHostPolicy())],
            new FixedProbeSettings(new ProbeSettings(null, $baseUrl, $hostHeader, $docroot, true, 0, false)),
            new FixedMagentoRoot(new MagentoRoot($this->store->path)),
            new ProbeScriptRenderer(),
            new ProbeScriptWriter(),
            new ProbeInterruptGuard(new ProbeScriptWriter()),
            new DirectProbeOutcomeFactory(),
            $this->progress,
        );
    }

    private function assertNoProbeFileIn(string $relative): void
    {
        self::assertSame(['.', '..'], scandir($this->store->path . '/' . $relative));
        self::assertSame([], $this->progress->warnings());
    }
}
