<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * How a command confirms which key ring the web tier holds.
 *
 * At most one transport is named: FastCGI with the PHP-FPM socket address (`unix:///path` or
 * `tcp://host:port`), or HTTP with a base URL, an optional Host header, the document root relative to
 * the Magento root (`pub` by default) and whether TLS certificates are verified. With neither, no probe
 * can be made.
 *
 * The host of the base URL and the Host header are each a host name, an IPv4 address or an IPv6
 * address in brackets, optionally followed by `:port`, and nothing else: no user information (`user@`),
 * no backslash, no whitespace, no path, query or fragment. A host the URL parser and the HTTP client
 * could read differently can therefore never slip past the check of where the probe is sent. A command may instead skip the probe, which the run records. The wait budget is how long
 * a command keeps asking before it gives up.
 *
 * Created through {@see ProbeSettingsFactory}.
 */
final class ProbeSettings
{
    public const DEFAULT_DOCROOT = 'pub';

    private const FASTCGI_ADDRESS = '~^(unix:///\S+|tcp://[^\s:/]+:[0-9]{1,5})$~D';
    private const BASE_URL = '~^https?://(?<authority>[^/?#\s]+)(?:/[^?#\s]*)?$~iD';
    private const LABEL = '[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?';
    private const AUTHORITY = '~^(?:(?<name>' . self::LABEL . '(?:\.' . self::LABEL . ')*\.?)|\[(?<ipv6>[0-9a-f:.]+)\])(?::(?<port>[0-9]{1,5}))?$~iD';
    private const MAX_HOST_NAME_LENGTH = 253;
    private const MAX_PORT = 65535;

    /**
     * @param string|null $fastCgiAddress the PHP-FPM socket, `unix:///path` or `tcp://host:port`
     * @param string|null $baseUrl        the base URL of the HTTP transport
     * @param string|null $hostHeader     the Host the HTTP transport asks for, when it differs from the URL's
     * @param string      $docroot        the document root of the HTTP transport, relative to the Magento root
     * @param bool        $verifyTls      whether the HTTP transport verifies TLS certificates
     * @param int         $waitSeconds    how long a command keeps asking before it gives up
     * @param bool        $skipped        whether the operator chose to skip the probe
     *
     * @throws InvalidValue when both transports are named, an address or URL is malformed, the docroot is
     *                      not relative or leaves the root, or the wait is negative
     */
    public function __construct(
        private readonly ?string $fastCgiAddress,
        private readonly ?string $baseUrl,
        private readonly ?string $hostHeader,
        private readonly string $docroot,
        private readonly bool $verifyTls,
        private readonly int $waitSeconds,
        private readonly bool $skipped,
    ) {
        if ($fastCgiAddress !== null && $baseUrl !== null) {
            throw new InvalidValue('A probe goes over FastCGI or over HTTP, not both.');
        }
        if ($fastCgiAddress !== null && preg_match(self::FASTCGI_ADDRESS, $fastCgiAddress) !== 1) {
            throw new InvalidValue(sprintf('A FastCGI address is unix:///path or tcp://host:port; "%s" is not.', $fastCgiAddress));
        }
        if ($baseUrl !== null && (preg_match(self::BASE_URL, $baseUrl, $url) !== 1 || !self::isAuthority($url['authority']))) {
            throw new InvalidValue(sprintf(
                'A probe base URL is http:// or https:// followed by a host name, an IPv4 address or a bracketed IPv6 address, an optional :port and an optional path; "%s" is not.',
                $baseUrl,
            ));
        }
        if ($hostHeader !== null && !self::isAuthority($hostHeader)) {
            throw new InvalidValue('A probe Host header is a host name, an IPv4 address or a bracketed IPv6 address, optionally followed by :port.');
        }
        if ($docroot === '' || str_starts_with($docroot, '/') || in_array('..', explode('/', $docroot), true)) {
            throw new InvalidValue(sprintf('The document root is a path inside the Magento root, relative to it; "%s" is not.', $docroot));
        }
        if ($waitSeconds < 0) {
            throw new InvalidValue('A probe wait cannot be negative.');
        }
    }

    /**
     * The transport the settings name, or null when they name none.
     */
    public function transport(): ?ProbeTransportKind
    {
        return match (true) {
            $this->fastCgiAddress !== null => ProbeTransportKind::FastCgi,
            $this->baseUrl !== null => ProbeTransportKind::Http,
            default => null,
        };
    }

    public function fastCgiAddress(): ?string
    {
        return $this->fastCgiAddress;
    }

    public function baseUrl(): ?string
    {
        return $this->baseUrl;
    }

    public function hostHeader(): ?string
    {
        return $this->hostHeader;
    }

    public function docroot(): string
    {
        return $this->docroot;
    }

    public function verifyTls(): bool
    {
        return $this->verifyTls;
    }

    public function waitSeconds(): int
    {
        return $this->waitSeconds;
    }

    public function isSkipped(): bool
    {
        return $this->skipped;
    }

    /**
     * Whether the text is a host name, an IPv4 address or a bracketed IPv6 address, with an optional
     * port from 1 to 65535, and nothing more.
     */
    private static function isAuthority(string $authority): bool
    {
        if (preg_match(self::AUTHORITY, $authority, $match, PREG_UNMATCHED_AS_NULL) !== 1) {
            return false;
        }
        if ($match['port'] !== null && ((int) $match['port'] < 1 || (int) $match['port'] > self::MAX_PORT)) {
            return false;
        }
        if ($match['ipv6'] !== null) {
            return filter_var($match['ipv6'], FILTER_VALIDATE_IP, FILTER_FLAG_IPV6) !== false;
        }

        return $match['name'] !== null && strlen(rtrim($match['name'], '.')) <= self::MAX_HOST_NAME_LENGTH;
    }
}
