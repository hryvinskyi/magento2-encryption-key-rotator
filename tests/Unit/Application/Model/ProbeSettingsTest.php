<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ProbeSettingsTest extends TestCase
{
    public function testAFastCgiAddressNamesTheFastCgiTransport(): void
    {
        self::assertSame(ProbeTransportKind::FastCgi, $this->settings(fastCgi: 'unix:///run/php/fpm.sock')->transport());
        self::assertSame(ProbeTransportKind::FastCgi, $this->settings(fastCgi: 'tcp://php-fpm:9000')->transport());
    }

    public function testABaseUrlNamesTheHttpTransport(): void
    {
        $settings = $this->settings(baseUrl: 'https://127.0.0.1:8443/store');

        self::assertSame(ProbeTransportKind::Http, $settings->transport());
        self::assertSame('pub', $settings->docroot());
    }

    public function testNeitherNamesNoTransport(): void
    {
        self::assertNull($this->settings()->transport());
        self::assertTrue($this->settings(skipped: true)->isSkipped());
    }

    /**
     * @return iterable<string, array{\Closure(self): ProbeSettings}>
     */
    public static function invalid(): iterable
    {
        yield 'both transports' => [static fn(self $t): ProbeSettings => $t->settings(fastCgi: 'tcp://fpm:9000', baseUrl: 'http://127.0.0.1')];
        yield 'a relative socket' => [static fn(self $t): ProbeSettings => $t->settings(fastCgi: 'unix://run/fpm.sock')];
        yield 'a TCP address without a port' => [static fn(self $t): ProbeSettings => $t->settings(fastCgi: 'tcp://fpm')];
        yield 'a bare path' => [static fn(self $t): ProbeSettings => $t->settings(fastCgi: '/run/fpm.sock')];
        yield 'a URL without a scheme' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: '127.0.0.1')];
        yield 'an absolute docroot' => [static fn(self $t): ProbeSettings => $t->settings(docroot: '/var/www/pub')];
        yield 'a docroot leaving the root' => [static fn(self $t): ProbeSettings => $t->settings(docroot: 'pub/../..')];
        yield 'a negative wait' => [static fn(self $t): ProbeSettings => $t->settings(wait: -1)];
        yield 'a Host header with a path' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test/x')];
        yield 'an empty Host header' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: '')];
        yield 'a Host header with user information' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'https://127.0.0.1', host: 'shop.test@8.8.8.8')];
        yield 'a Host header with a backslash' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'https://127.0.0.1', host: 'shop.test\\@8.8.8.8')];
        yield 'a Host header with whitespace' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: "shop.test\r\nX-Evil: 1")];
        yield 'a Host header with a query' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test?x')];
        yield 'a Host header with a fragment' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test#x')];
        yield 'a Host header with an unbracketed IPv6 address' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: '::1')];
        yield 'a Host header with a malformed bracketed address' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: '[1.2.3.4]')];
        yield 'a Host header with port 0' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test:0')];
        yield 'a Host header with a port out of range' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test:65536')];
        yield 'a Host header with an empty port' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop.test:')];
        yield 'a Host header with a label starting with a dash' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: '-shop.test')];
        yield 'a Host header with an empty label' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1', host: 'shop..test')];
        yield 'a base URL with user information' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://8.8.8.8@127.0.0.1/')];
        yield 'a base URL with a backslash before the host' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1\\@8.8.8.8/')];
        yield 'a base URL with a query' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1/?x=1')];
        yield 'a base URL with a fragment' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1#@8.8.8.8')];
        yield 'a base URL with a port out of range' => [static fn(self $t): ProbeSettings => $t->settings(baseUrl: 'http://127.0.0.1:99999')];
    }

    /**
     * @return iterable<string, array{string, ?string}>
     */
    public static function valid(): iterable
    {
        yield 'a host name' => ['http://127.0.0.1', 'shop.example.com'];
        yield 'a host name with a port' => ['http://127.0.0.1', 'shop.example.com:8443'];
        yield 'a host name with the root dot' => ['http://127.0.0.1', 'localhost.'];
        yield 'a host name in upper case' => ['http://127.0.0.1', 'Shop.Example.COM'];
        yield 'a service name with an underscore' => ['http://127.0.0.1', 'php_fpm'];
        yield 'an IPv4 address with a port' => ['http://127.0.0.1', '10.0.0.5:80'];
        yield 'a bracketed IPv6 address' => ['http://127.0.0.1', '[::1]'];
        yield 'a bracketed IPv6 address with a port' => ['http://127.0.0.1', '[fd00::1]:8443'];
        yield 'a base URL with a bracketed IPv6 address and a path' => ['https://[::1]:8443/store/', null];
        yield 'a base URL with a service name' => ['http://web', null];
    }

    #[DataProvider('valid')]
    public function testAHostNameOrAnAddressWithAnOptionalPortIsAccepted(string $baseUrl, ?string $host): void
    {
        $settings = $this->settings(baseUrl: $baseUrl, host: $host);

        self::assertSame($baseUrl, $settings->baseUrl());
        self::assertSame($host, $settings->hostHeader());
    }

    /**
     * @param \Closure(self): ProbeSettings $make
     */
    #[DataProvider('invalid')]
    public function testContradictoryOrMalformedSettingsAreRefused(\Closure $make): void
    {
        $this->expectException(InvalidValue::class);

        $make($this);
    }

    public function settings(
        ?string $fastCgi = null,
        ?string $baseUrl = null,
        ?string $host = null,
        string $docroot = ProbeSettings::DEFAULT_DOCROOT,
        int $wait = 30,
        bool $skipped = false,
    ): ProbeSettings {
        return new ProbeSettings($fastCgi, $baseUrl, $host, $docroot, true, $wait, $skipped);
    }
}
