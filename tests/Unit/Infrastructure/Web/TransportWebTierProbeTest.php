<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeInterruptGuard;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\TransportWebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RingAnsweringProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

/**
 * The probe picks the first transport that supports the settings, writes a one-time file for it, judges
 * the answer by an HMAC under a one-time token, and never leaves the file behind.
 */
final class TransportWebTierProbeTest extends TestCase
{
    private ProbeStoreRoot $store;

    private string $scripts;

    private KeyRing $ring;

    private FixedProbeSettings $settings;

    private RecordingProgress $progress;

    protected function setUp(): void
    {
        $cryptKey = KeyMaterial::rawKey() . "\n" . KeyMaterial::base64Key();
        $this->store = ProbeStoreRoot::create($cryptKey);
        $this->ring = ProbeStoreRoot::ring($cryptKey);
        $this->scripts = TemporaryDirectory::create('key-rotator-probe-scripts');
        $this->settings = new FixedProbeSettings();
        $this->progress = new RecordingProgress();
    }

    protected function tearDown(): void
    {
        $this->store->remove();
        TemporaryDirectory::remove($this->scripts);
    }

    public function testAWebTierHoldingTheExpectedRingMatches(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Matches, $outcome->status());
        self::assertSame([], $this->progress->warnings());
    }

    public function testAWebTierHoldingAnotherRingDiffersAndSaysWhatToDo(): void
    {
        $other = ProbeStoreRoot::ring(KeyMaterial::rawKey());
        $transport = $this->transport(ProbeTransportKind::FastCgi, $other->export());

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Differs, $outcome->status());
        self::assertStringContainsString('reload PHP-FPM or reset opcache', $outcome->reason());
    }

    public function testTheProbeFileIsReadableByTheWebTierKnowsTheDeploymentConfigAndIsGoneAfterwards(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());

        $this->probe($transport)->observe($this->ring);

        $fetch = $transport->fetches()[0];
        self::assertTrue($fetch['existed']);
        self::assertSame(ProbeScriptWriter::MODE, $fetch['mode']);
        self::assertMatchesRegularExpression('~^' . preg_quote($this->scripts, '~') . '/key-rotator-probe-[0-9a-f]{32}\.php$~', $fetch['path']);
        self::assertMatchesRegularExpression('/^t=[0-9a-f]{64}$/', $fetch['query']);
        self::assertStringContainsString(var_export($this->store->deploymentConfigFile(), true), $fetch['source']);
        self::assertStringContainsString(var_export(substr($fetch['query'], 2), true), $fetch['source']);
        self::assertFileDoesNotExist($fetch['path']);
        self::assertSame(['.', '..'], scandir($this->scripts));
    }

    public function testEveryObservationUsesAFreshFileNameAndToken(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $probe = $this->probe($transport);

        $probe->observe($this->ring);
        $probe->observe($this->ring);

        [$first, $second] = $transport->fetches();
        self::assertNotSame($first['path'], $second['path']);
        self::assertNotSame($first['query'], $second['query']);
    }

    public function testTheFirstTransportThatSupportsTheSettingsIsUsed(): void
    {
        $http = $this->transport(ProbeTransportKind::Http, $this->ring->export());
        $fastCgi = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $secondFastCgi = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());

        $outcome = $this->probe($http, $fastCgi, $secondFastCgi)->observe($this->ring);

        self::assertSame(ProbeStatus::Matches, $outcome->status());
        self::assertSame([], $http->fetches());
        self::assertCount(1, $fastCgi->fetches());
        self::assertSame([], $secondFastCgi->fetches());
    }

    public function testWithoutASupportingTransportTheWebTierIsUnreachableAndNothingIsWritten(): void
    {
        $this->settings->replace(new ProbeSettings(null, null, null, ProbeSettings::DEFAULT_DOCROOT, true, 0, false));
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('No probe transport configured', $outcome->reason());
        self::assertSame([], $transport->fetches());
        self::assertSame(['.', '..'], scandir($this->scripts));
    }

    public function testAnAnswerLargerThanTheProbeEverSendsIsUnreachable(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $transport->answerWith(str_repeat('a', TransportWebTierProbe::MAX_ANSWER_BYTES + 1));

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString('129 bytes', $outcome->reason());
        self::assertSame(['.', '..'], scandir($this->scripts));
    }

    public function testAShortAnswerThatIsNotAnHmacIsUnreachable(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $transport->answerWith('File not found.');

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
    }

    public function testATransportFailureIsUnreachableWithItsReasonAndTheFileIsStillDeleted(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $transport->failWith('PHP-FPM at unix:///nowhere.sock could not be reached: no such file');

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertSame('PHP-FPM at unix:///nowhere.sock could not be reached: no such file', $outcome->reason());
        self::assertTrue($transport->fetches()[0]['existed']);
        self::assertSame(['.', '..'], scandir($this->scripts));
    }

    public function testAProbeFileThatCannotBeDeletedIsAWarningNamingItsPath(): void
    {
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());
        $transport->replaceProbeFileWithDirectory();

        $outcome = $this->probe($transport)->observe($this->ring);

        $path = $transport->fetches()[0]['path'];
        self::assertSame(ProbeStatus::Matches, $outcome->status());
        self::assertCount(1, $this->progress->warnings());
        self::assertStringContainsString($path, $this->progress->warnings()[0]);
        self::assertStringContainsString('could not be deleted', $this->progress->warnings()[0]);
    }

    public function testProbeFilesAnInterruptedProbeLeftAreDeletedBeforeTheNextOneAndNothingElse(): void
    {
        $stale = 'key-rotator-probe-' . str_repeat('ab', 16) . '.php';
        $staleTemporary = '.key-rotator-probe-' . str_repeat('cd', 16) . '.php.tmp';
        $kept = [
            'index.php',
            'key-rotator-probe-short.php',
            'key-rotator-probe-' . str_repeat('ab', 16) . '.php.bak',
            'key-rotator-probe-' . str_repeat('a', 31) . '.php',
            'key-rotator-probe-' . str_repeat('g', 32) . '.php',
            '.key-rotator-probe-' . str_repeat('cd', 16) . '.php',
        ];
        foreach ([$stale, $staleTemporary, ...$kept] as $name) {
            file_put_contents($this->scripts . '/' . $name, '<?php');
        }
        $directory = 'key-rotator-probe-' . str_repeat('ef', 16) . '.php';
        mkdir($this->scripts . '/' . $directory);
        $transport = $this->transport(ProbeTransportKind::FastCgi, $this->ring->export());

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Matches, $outcome->status());
        self::assertSame([], $this->progress->warnings());
        $left = array_values(array_diff(scandir($this->scripts) ?: [], ['.', '..']));
        sort($left);
        $expected = [...$kept, $directory];
        sort($expected);
        self::assertSame($expected, $left);
    }

    public function testAnUnwritableScriptDirectoryIsUnreachable(): void
    {
        $transport = new RingAnsweringProbeTransport(ProbeTransportKind::FastCgi, $this->scripts . '/missing', $this->ring->export());

        $outcome = $this->probe($transport)->observe($this->ring);

        self::assertSame(ProbeStatus::Unreachable, $outcome->status());
        self::assertStringContainsString($this->scripts . '/missing', $outcome->reason());
        self::assertSame([], $transport->fetches());
    }

    private function transport(ProbeTransportKind $kind, string $ring): RingAnsweringProbeTransport
    {
        return new RingAnsweringProbeTransport($kind, $this->scripts, $ring);
    }

    private function probe(ProbeTransport ...$transports): TransportWebTierProbe
    {
        return new TransportWebTierProbe(
            $transports,
            $this->settings,
            new FixedMagentoRoot(new MagentoRoot($this->store->path)),
            new ProbeScriptRenderer(),
            new ProbeScriptWriter(),
            new ProbeInterruptGuard(new ProbeScriptWriter()),
            new DirectProbeOutcomeFactory(),
            $this->progress,
        );
    }
}
