<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeHostPolicy;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * An HTTP probe goes only to loopback and private addresses and to single-label names; a public host
 * would route it through whatever answers for that host publicly.
 */
final class ProbeHostPolicyTest extends TestCase
{
    /**
     * @return iterable<string, array{string}>
     */
    public static function allowedHosts(): iterable
    {
        yield 'IPv4 loopback' => ['127.0.0.1'];
        yield 'another IPv4 loopback' => ['127.1.2.3'];
        yield 'IPv4 private, 10/8' => ['10.0.0.5'];
        yield 'IPv4 private, 172.16/12' => ['172.16.4.4'];
        yield 'IPv4 private, 192.168/16' => ['192.168.1.1'];
        yield 'IPv6 loopback' => ['::1'];
        yield 'IPv6 loopback in brackets' => ['[::1]'];
        yield 'IPv6 unique local' => ['fd00::1'];
        yield 'localhost' => ['localhost'];
        yield 'localhost with the root dot' => ['localhost.'];
        yield 'a service name' => ['web'];
        yield 'a service name with a dash' => ['php-fpm'];
        yield 'an IPv4-mapped loopback' => ['::ffff:127.0.0.1'];
        yield 'an IPv4-mapped private address in brackets' => ['[::ffff:10.1.2.3]'];
        yield 'an IPv4-mapped private address in hex' => ['::ffff:c0a8:101'];
        yield 'a NAT64 address of a private one' => ['64:ff9b::10.0.0.7'];
        yield 'a service name that merely starts with digits' => ['8web'];
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function refusedHosts(): iterable
    {
        yield 'a public host name' => ['shop.example.com'];
        yield 'a two-label name' => ['store.test'];
        yield 'a public IPv4 address' => ['8.8.8.8'];
        yield 'a public IPv6 address' => ['2001:4860:4860::8888'];
        yield 'nothing' => [''];
        yield 'an IPv4-mapped public address' => ['::ffff:8.8.8.8'];
        yield 'an IPv4-mapped public address in brackets' => ['[::ffff:8.8.8.8]'];
        yield 'an IPv4-mapped public address in hex' => ['::ffff:808:808'];
        yield 'an IPv4-translated public address' => ['::ffff:0:8.8.8.8'];
        yield 'an IPv4-compatible public address' => ['::8.8.8.8'];
        yield 'a NAT64 address of a public one' => ['64:ff9b::8.8.8.8'];
        yield 'a NAT64 address of a public one in hex' => ['[64:ff9b::808:808]'];
        yield 'a public IPv4 address as one integer' => ['134744072'];
        yield 'a public IPv4 address as one hex number' => ['0x8080808'];
        yield 'a public IPv4 address as one octal number' => ['01002004010'];
        yield 'only the root dot' => ['.'];
    }

    #[DataProvider('allowedHosts')]
    public function testAllowsLoopbackPrivateAndSingleLabelHosts(string $host): void
    {
        self::assertTrue((new ProbeHostPolicy())->allows($host));
    }

    #[DataProvider('refusedHosts')]
    public function testRefusesPublicHosts(string $host): void
    {
        self::assertFalse((new ProbeHostPolicy())->allows($host));
    }
}
