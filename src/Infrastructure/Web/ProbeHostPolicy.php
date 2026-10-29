<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

/**
 * Which hosts an HTTP probe may be sent to: a loopback or private address, or a single-label name
 * (`localhost`, a container's service name). A public host name would send the request through
 * whatever answers for it publicly, a CDN or a cache in front of another server, which proves nothing
 * about this host's PHP.
 *
 * An IPv6 address that carries an IPv4 address (IPv4-mapped `::ffff:a.b.c.d`, IPv4-translated
 * `::ffff:0:a.b.c.d`, IPv4-compatible `::a.b.c.d` and the NAT64 prefix `64:ff9b::/96`) is judged by the
 * IPv4 address it carries, since that is where a connection to it goes. A single label made of digits,
 * or `0x` and hex digits, is an IPv4 address in the integer, octal or hex form an HTTP client also
 * accepts, never a name, and is refused.
 */
final class ProbeHostPolicy
{
    private const IPV4_MAPPED = "\0\0\0\0\0\0\0\0\0\0\xff\xff";
    private const IPV4_TRANSLATED = "\0\0\0\0\0\0\0\0\xff\xff\0\0";
    private const IPV4_COMPATIBLE = "\0\0\0\0\0\0\0\0\0\0\0\0";
    private const NAT64_WELL_KNOWN = "\x00\x64\xff\x9b\0\0\0\0\0\0\0\0";
    private const EMBEDDING_PREFIX_BYTES = 12;
    private const NUMERIC_LABEL = '/^(?:[0-9]+|0x[0-9a-f]*)$/D';

    /**
     * @param string $host a host name or an address, an IPv6 address with or without its brackets
     */
    public function allows(string $host): bool
    {
        $host = strtolower(trim($host, '[]'));
        if ($host === '') {
            return false;
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV4) !== false) {
            return $this->isLocal($host);
        }
        if (filter_var($host, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false) {
            return $this->isLocal($this->embeddedIpv4($host) ?? $host);
        }

        $name = rtrim($host, '.');

        return $name !== '' && !str_contains($name, '.') && preg_match(self::NUMERIC_LABEL, $name) !== 1;
    }

    /**
     * Whether a valid address is a loopback, private or reserved one.
     */
    private function isLocal(string $address): bool
    {
        return filter_var($address, FILTER_VALIDATE_IP, FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE) === false;
    }

    /**
     * The IPv4 address a valid IPv6 address carries, or null when it carries none.
     */
    private function embeddedIpv4(string $ipv6): ?string
    {
        $bytes = inet_pton($ipv6);
        if ($bytes === false || strlen($bytes) !== 16) {
            return null;
        }
        $prefix = substr($bytes, 0, self::EMBEDDING_PREFIX_BYTES);
        if (!in_array($prefix, [self::IPV4_MAPPED, self::IPV4_TRANSLATED, self::IPV4_COMPATIBLE, self::NAT64_WELL_KNOWN], true)) {
            return null;
        }
        $ipv4 = inet_ntop(substr($bytes, self::EMBEDDING_PREFIX_BYTES));

        return $ipv4 === false ? null : $ipv4;
    }
}
