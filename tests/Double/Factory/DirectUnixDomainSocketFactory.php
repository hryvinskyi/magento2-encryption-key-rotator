<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use hollodotme\FastCGI\SocketConnections\UnixDomainSocket;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\UnixDomainSocketFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectUnixDomainSocketFactory implements UnixDomainSocketFactory
{
    public function create(string $socketPath, int $connectTimeout, int $readWriteTimeout): UnixDomainSocket
    {
        return new UnixDomainSocket($socketPath, $connectTimeout, $readWriteTimeout);
    }
}
