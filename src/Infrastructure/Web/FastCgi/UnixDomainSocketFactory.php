<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi;

use hollodotme\FastCGI\SocketConnections\UnixDomainSocket;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates the connection to a PHP-FPM pool listening on a unix domain socket; implemented by the
 * container build.
 */
#[CreatesInstancesOf(UnixDomainSocket::class)]
interface UnixDomainSocketFactory
{
    /**
     * @param string $socketPath       the socket file, without the `unix://` scheme
     * @param int    $connectTimeout   milliseconds to wait for the connection
     * @param int    $readWriteTimeout milliseconds to wait for every read and write
     */
    public function create(string $socketPath, int $connectTimeout, int $readWriteTimeout): UnixDomainSocket;
}
