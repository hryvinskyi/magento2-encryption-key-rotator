<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

use hollodotme\FastCGI\Exceptions\FastCGIClientException;
use hollodotme\FastCGI\Exceptions\TimedoutException;
use hollodotme\FastCGI\Interfaces\ConfiguresSocketConnection;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RunDirectoryLayout;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\UntrustedStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\ClientFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\GetRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\NetworkSocketFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\UnixDomainSocketFactory;

/**
 * Runs the probe file by talking FastCGI straight to the PHP-FPM pool's socket.
 *
 * A web server in front of the pool is never involved: a server that passes only the store's entry
 * points to PHP and denies every other `.php` cannot stop the probe, and no proxy, cache or CDN sees
 * the request. The file lives in `<state directory>/probe/`, outside the document root, in a directory
 * of mode 0711: the pool's user can read a file whose name it is given but cannot list the directory.
 * The state directory and the probe directory are checked like every other part of the state directory
 * ({@see RunDirectoryLayout}): one another account could write, or a symbolic link, is refused before a
 * file is written there.
 *
 * The pool's user must be able to enter the state directory to reach the file. The connection waits 3 s
 * for the socket and 10 s for every read. A pool that refuses the script (`open_basedir`,
 * `security.limit_extensions`, a chroot that hides the directory, a user who cannot enter it) answers
 * with a status line, which is reported as it is.
 */
final class FastCgiProbeTransport implements ProbeTransport
{
    public const DIRECTORY = RunDirectoryLayout::PROBE_DIRECTORY;
    public const DIRECTORY_MODE = RunDirectoryLayout::PROBE_DIRECTORY_MODE;
    public const CONNECT_TIMEOUT_MS = 3000;
    public const READ_TIMEOUT_MS = 10000;

    private const TCP_ADDRESS = '~^tcp://([^\s:/]+):([0-9]{1,5})$~D';
    private const UNIX_SCHEME = 'unix://';

    /**
     * @param int $connectTimeoutMs milliseconds to wait for the socket
     * @param int $readTimeoutMs    milliseconds to wait for every read and write
     */
    public function __construct(
        private readonly RunDirectoryLayout $layout,
        private readonly UnixDomainSocketFactory $unixSockets,
        private readonly NetworkSocketFactory $networkSockets,
        private readonly GetRequestFactory $requests,
        private readonly ClientFactory $clients,
        private readonly int $connectTimeoutMs = self::CONNECT_TIMEOUT_MS,
        private readonly int $readTimeoutMs = self::READ_TIMEOUT_MS,
    ) {}

    public function supports(ProbeSettings $settings): bool
    {
        return $settings->transport() === ProbeTransportKind::FastCgi;
    }

    /**
     * {@inheritDoc}
     *
     * @throws UntrustedStateDirectory when the state directory or the probe directory is not safe
     */
    public function scriptDirectory(ProbeSettings $settings): string
    {
        try {
            return $this->layout->ensureProbeDirectory();
        } catch (FilesystemFailure $failure) {
            throw new ProbeUnreachable(sprintf('The probe directory cannot be prepared: %s', $failure->getMessage()), 0, $failure);
        }
    }

    public function fetch(ProbeSettings $settings, string $directory, string $fileName, string $query): string
    {
        $address = $settings->fastCgiAddress()
            ?? throw new ProbeUnreachable('The probe settings name no PHP-FPM address.');
        $script = $directory . '/' . $fileName;

        $request = $this->requests->create($script, '');
        $request->setRequestUri('/' . $fileName . '?' . $query);
        $request->addCustomVars([
            'QUERY_STRING' => $query,
            'SCRIPT_NAME' => '/' . $fileName,
            'DOCUMENT_ROOT' => $directory,
        ]);

        try {
            $response = $this->clients->create()->sendRequest($this->connection($address), $request);
        } catch (TimedoutException) {
            throw new ProbeUnreachable(sprintf(
                'PHP-FPM at %s did not answer the probe within %d s.',
                $address,
                intdiv($this->readTimeoutMs, 1000),
            ));
        } catch (FastCGIClientException $failure) {
            throw new ProbeUnreachable(sprintf('PHP-FPM at %s could not be reached: %s', $address, $failure->getMessage()));
        }

        $status = trim($response->getHeaderLine('Status'));
        if ($status !== '' && !str_starts_with($status, '200')) {
            throw new ProbeUnreachable(sprintf(
                'PHP-FPM at %s refused the probe script with "%s": a pool restricted by open_basedir, '
                . 'security.limit_extensions or a chroot, or running as a user who cannot enter %s, cannot run %s.',
                $address,
                $status,
                dirname($directory),
                $script,
            ));
        }

        return $response->getBody();
    }

    private function connection(string $address): ConfiguresSocketConnection
    {
        if (str_starts_with($address, self::UNIX_SCHEME)) {
            return $this->unixSockets->create(
                substr($address, strlen(self::UNIX_SCHEME)),
                $this->connectTimeoutMs,
                $this->readTimeoutMs,
            );
        }
        if (preg_match(self::TCP_ADDRESS, $address, $match) !== 1) {
            throw new ProbeUnreachable(sprintf('"%s" is not a PHP-FPM address: give unix:///path or tcp://host:port.', $address));
        }

        return $this->networkSockets->create($match[1], (int) $match[2], $this->connectTimeoutMs, $this->readTimeoutMs);
    }
}
