<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi;

use hollodotme\FastCGI\SocketConnections\NetworkSocket;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates the connection to a PHP-FPM pool listening on a TCP port; implemented by the container build.
 */
#[CreatesInstancesOf(NetworkSocket::class)]
interface NetworkSocketFactory
{
    /**
     * @param int $connectTimeout   milliseconds to wait for the connection
     * @param int $readWriteTimeout milliseconds to wait for every read and write
     */
    public function create(string $host, int $port, int $connectTimeout, int $readWriteTimeout): NetworkSocket;
}
