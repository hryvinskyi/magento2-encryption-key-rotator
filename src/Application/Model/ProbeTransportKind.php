<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * How the web tier is reached to confirm the key ring it holds: FastCGI straight to the PHP-FPM
 * socket, or HTTP to a probe file in the document root.
 */
enum ProbeTransportKind: string
{
    case FastCgi = 'fastcgi';
    case Http = 'http';
}
