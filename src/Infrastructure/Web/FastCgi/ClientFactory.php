<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi;

use hollodotme\FastCGI\Client;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates FastCGI clients; implemented by the container build. A client keeps its sockets, so every
 * probe takes a fresh one rather than reusing a connection the pool may have closed.
 */
#[CreatesInstancesOf(Client::class)]
interface ClientFactory
{
    public function create(): Client;
}
