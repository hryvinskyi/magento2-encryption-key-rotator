<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\HttpProbeTransport;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeHostPolicy;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeUnreachable;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\FixedMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ProbeStoreRoot;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpClient\MockHttpClient;
use Symfony\Component\HttpClient\Response\MockResponse;

/**
 * The request the HTTP probe sends: never through a proxy, and over TLS with a Host header, pinned
 * exactly to the host it asks for.
 */
final class HttpProbeTransportTest extends TestCase
{
    /**
     * @var list<array{url: string, options: array<mixed>}>
     */
    private array $requests = [];

    private ProbeStoreRoot $store;

    protected function setUp(): void
    {
        $this->store = ProbeStoreRoot::create(KeyMaterial::base64Key());
    }

    protected function tearDown(): void
    {
        $this->store->remove();
    }

    public function testNoProxyEverCarriesTheProbe(): void
    {
        $this->fetch(new ProbeSettings(null, 'http://127.0.0.1:8080', null, 'pub', true, 0, false));

        self::assertSame('*', $this->requests[0]['options']['no_proxy']);
        self::assertSame('http://127.0.0.1:8080/probe.php?t=token', $this->requests[0]['url']);
    }

    public function testOverTlsTheHostHeaderBecomesTheUrlHostPinnedToTheBaseAddress(): void
    {
        $this->fetch(new ProbeSettings(null, 'https://10.0.0.5:8443/store', 'Shop.Example.COM', 'pub', true, 0, false));

        $request = $this->requests[0];
        self::assertSame('https://shop.example.com:8443/store/probe.php?t=token', $request['url']);
        self::assertSame(['shop.example.com' => '10.0.0.5'], $request['options']['resolve']);
    }

    public function testOverTlsAHostHeaderThatIsAPublicAddressIsRefused(): void
    {
        try {
            $this->fetch(new ProbeSettings(null, 'https://127.0.0.1', '8.8.8.8:443', 'pub', true, 0, false));
            self::fail('A probe was sent to a public address named by the Host header.');
        } catch (ProbeUnreachable $refused) {
            self::assertStringContainsString('public address 8.8.8.8', $refused->getMessage());
        }

        self::assertSame([], $this->requests);
    }

    public function testOverTlsAHostHeaderThatIsAMappedPublicAddressIsRefused(): void
    {
        $this->expectException(ProbeUnreachable::class);

        $this->fetch(new ProbeSettings(null, 'https://127.0.0.1', '[::ffff:8.8.8.8]', 'pub', true, 0, false));
    }

    public function testOverTlsAHostHeaderThatIsALocalAddressIsAllowed(): void
    {
        $this->fetch(new ProbeSettings(null, 'https://127.0.0.1', '[::1]', 'pub', true, 0, false));

        self::assertSame('https://[::1]/probe.php?t=token', $this->requests[0]['url']);
    }

    public function testAPublicIpv4MappedBaseAddressIsRefused(): void
    {
        $this->expectException(ProbeUnreachable::class);
        $this->expectExceptionMessage('public host');

        $this->fetch(new ProbeSettings(null, 'http://[::ffff:8.8.8.8]', null, 'pub', true, 0, false));
    }

    private function fetch(ProbeSettings $settings): string
    {
        $client = new MockHttpClient(function (string $method, string $url, array $options): MockResponse {
            $this->requests[] = ['url' => $url, 'options' => $options];

            return new MockResponse(str_repeat('a', 64));
        });
        $transport = new HttpProbeTransport(new FixedMagentoRoot(new MagentoRoot($this->store->path)), $client, new ProbeHostPolicy());

        return $transport->fetch($settings, $this->store->path . '/pub', 'probe.php', 't=token');
    }
}
