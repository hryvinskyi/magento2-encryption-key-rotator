<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use hollodotme\FastCGI\Requests\GetRequest;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi\GetRequestFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectGetRequestFactory implements GetRequestFactory
{
    public function create(string $scriptFilename, string $content): GetRequest
    {
        return new GetRequest($scriptFilename, $content);
    }
}
