<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see PurgeRequest} values; implemented by the container build.
 */
#[CreatesInstancesOf(PurgeRequest::class)]
interface PurgeRequestFactory
{
    public function create(?RunId $runId, bool $acceptLoss): PurgeRequest;
}
