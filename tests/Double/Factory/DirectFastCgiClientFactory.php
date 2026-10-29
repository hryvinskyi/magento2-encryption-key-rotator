<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use hollodotme\FastCGI\Client;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\ClientFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectFastCgiClientFactory implements ClientFactory
{
    public function create(): Client
    {
        return new Client();
    }
}
