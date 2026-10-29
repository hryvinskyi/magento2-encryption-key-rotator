<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use hollodotme\FastCGI\SocketConnections\NetworkSocket;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\NetworkSocketFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectNetworkSocketFactory implements NetworkSocketFactory
{
    public function create(string $host, int $port, int $connectTimeout, int $readWriteTimeout): NetworkSocket
    {
        return new NetworkSocket($host, $port, $connectTimeout, $readWriteTimeout);
    }
}
