<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Symfony\Contracts\HttpClient\Exception\TransportExceptionInterface;
use Symfony\Contracts\HttpClient\HttpClientInterface;

/**
 * Runs the probe file through the web server: the file goes into the document root and is requested as
 * `GET <base URL>/<name>.php?<query>`.
 *
 * This works only where the web server hands any `.php` file to PHP. A server that runs only the
 * store's entry points answers 404 or 403 for the probe file; the reason says so and names the FastCGI
 * transport, which does not depend on the web server.
 *
 * The base URL must name a loopback or private address or a single-label host: a public host name would
 * route the request through a CDN or a cache. A Host header given for an HTTPS base URL becomes the
 * request's host name, resolved to the base URL's address, so the TLS server name and the certificate
 * match; over plain HTTP it is sent as the Host header. The request waits at most 3 s without data
 * (connecting included) and 10 s in all, follows no redirect, and verifies TLS unless told not to.
 *
 * The request never goes through a proxy, whatever `http_proxy`, `https_proxy` or `all_proxy` the
 * environment sets: a proxy would see the probe's token and could answer in the web tier's place. Over
 * TLS with a Host header, the host name pinned to the base URL's address is exactly the host of the
 * URL requested, lower-cased as the client compares it; a Host header that is itself an address is
 * connected to directly, so it must pass the same host rule as the base URL.
 */
final class HttpProbeTransport implements ProbeTransport
{
    public const IDLE_TIMEOUT_SECONDS = 3.0;
    public const TOTAL_TIMEOUT_SECONDS = 10.0;

    private const NOT_EXECUTED = 'The web server answered HTTP %d for the probe file: the document root (--docroot) or the '
        . 'base URL (--probe-url) is wrong, or the web server does not run arbitrary .php files, as a server '
        . 'configured to run only the store\'s entry points does not. Probe PHP-FPM directly with --probe-fcgi.';

    public function __construct(
        private readonly MagentoRootProvider $roots,
        private readonly HttpClientInterface $http,
        private readonly ProbeHostPolicy $hosts,
    ) {}

    public function supports(ProbeSettings $settings): bool
    {
        return $settings->transport() === ProbeTransportKind::Http;
    }

    public function scriptDirectory(ProbeSettings $settings): string
    {
        $this->allowedBase($settings);
        $directory = $this->roots->root()->file($settings->docroot());
        if (!is_dir($directory)) {
            throw new ProbeUnreachable(sprintf(
                'The document root %s does not exist: give --docroot relative to the Magento root.',
                $directory,
            ));
        }

        return rtrim($directory, '/');
    }

    public function fetch(ProbeSettings $settings, string $directory, string $fileName, string $query): string
    {
        $request = $this->request($this->allowedBase($settings), $settings);
        $url = $request['url'] . '/' . $fileName . '?' . $query;

        try {
            $response = $this->http->request('GET', $url, $request['options']);
            $status = $response->getStatusCode();
            $body = $response->getContent(false);
        } catch (TransportExceptionInterface $failure) {
            throw new ProbeUnreachable(sprintf(
                'No answer from %s: %s',
                $settings->baseUrl(),
                str_replace($query, 't=[redacted]', $failure->getMessage()),
            ));
        }

        if ($status === 404 || $status === 403) {
            throw new ProbeUnreachable(sprintf(self::NOT_EXECUTED, $status));
        }
        if ($status >= 300 && $status < 400) {
            throw new ProbeUnreachable(sprintf(
                'The web server answered HTTP %d, a redirect, which the probe does not follow: give the final address as --probe-url.',
                $status,
            ));
        }
        if ($status !== 200) {
            throw new ProbeUnreachable(sprintf('The web server answered the probe with HTTP %d.', $status));
        }

        return $body;
    }

    /**
     * @return array{scheme: string, host: string, port: int|null, path: string}
     *
     * @throws ProbeUnreachable when no base URL is given or its host is public
     */
    private function allowedBase(ProbeSettings $settings): array
    {
        $url = $settings->baseUrl() ?? throw new ProbeUnreachable('The probe settings name no base URL.');
        $parts = parse_url($url);
        if (!is_array($parts) || !isset($parts['scheme'], $parts['host'])) {
            throw new ProbeUnreachable(sprintf('The probe base URL %s names no host.', $url));
        }
        if (!$this->hosts->allows($parts['host'])) {
            throw new ProbeUnreachable(sprintf(
                'The probe base URL %s names the public host %s, whose requests may be answered by a CDN or a cache: '
                . 'give a loopback or private address with --probe-url, the store\'s host name with --probe-host, or use --probe-fcgi.',
                $url,
                $parts['host'],
            ));
        }

        return [
            'scheme' => strtolower($parts['scheme']),
            'host' => $parts['host'],
            'port' => $parts['port'] ?? null,
            'path' => rtrim($parts['path'] ?? '', '/'),
        ];
    }

    /**
     * The base URL to request and the request options: the timeouts, no redirects, TLS verification
     * and what the Host header needs.
     *
     * @param array{scheme: string, host: string, port: int|null, path: string} $base
     *
     * @return array{url: string, options: array<string, mixed>}
     *
     * @throws ProbeUnreachable when an HTTPS base URL's host cannot be resolved, or the Host header is a public address
     */
    private function request(array $base, ProbeSettings $settings): array
    {
        $options = [
            'timeout' => self::IDLE_TIMEOUT_SECONDS,
            'max_duration' => self::TOTAL_TIMEOUT_SECONDS,
            'max_redirects' => 0,
            'verify_peer' => $settings->verifyTls(),
            'verify_host' => $settings->verifyTls(),
            'headers' => ['Cache-Control' => 'no-cache'],
            'proxy' => null,
            'no_proxy' => '*',
        ];
        $port = $base['port'] === null ? '' : ':' . $base['port'];
        $hostHeader = $settings->hostHeader();
        if ($hostHeader === null) {
            return ['url' => $base['scheme'] . '://' . $base['host'] . $port . $base['path'], 'options' => $options];
        }
        if ($base['scheme'] !== 'https') {
            $options['headers']['Host'] = $hostHeader;

            return ['url' => $base['scheme'] . '://' . $base['host'] . $port . $base['path'], 'options' => $options];
        }

        // Over TLS the name asked for must be the one the certificate carries: it becomes the URL's host,
        // pinned to the base URL's address.
        $name = strtolower((string) preg_replace('/:\d+$/', '', $hostHeader));
        if (filter_var(trim($name, '[]'), FILTER_VALIDATE_IP) !== false && !$this->hosts->allows($name)) {
            throw new ProbeUnreachable(sprintf(
                'The probe Host header %s is the public address %s, which an HTTPS probe connects to directly: '
                . 'give the store\'s host name with --probe-host, or use --probe-fcgi.',
                $hostHeader,
                $name,
            ));
        }
        $options['resolve'] = [$name => $this->address($base['host'])];

        return ['url' => 'https://' . $name . $port . $base['path'], 'options' => $options];
    }

    private function address(string $host): string
    {
        $host = trim($host, '[]');
        if (filter_var($host, FILTER_VALIDATE_IP) !== false) {
            return $host;
        }
        $address = gethostbyname($host);
        if ($address === $host) {
            throw new ProbeUnreachable(sprintf('The probe base URL\'s host %s cannot be resolved.', $host));
        }

        return $address;
    }
}
