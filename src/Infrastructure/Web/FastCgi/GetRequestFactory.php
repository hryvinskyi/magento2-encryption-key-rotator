<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\FastCgi;

use hollodotme\FastCGI\Requests\GetRequest;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates FastCGI GET requests; implemented by the container build.
 */
#[CreatesInstancesOf(GetRequest::class)]
interface GetRequestFactory
{
    /**
     * @param string $scriptFilename the absolute path of the script the pool runs
     * @param string $content        the request body
     */
    public function create(string $scriptFilename, string $content): GetRequest;
}
