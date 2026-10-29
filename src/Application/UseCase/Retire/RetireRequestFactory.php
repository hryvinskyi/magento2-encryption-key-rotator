<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RetireRequest} values; implemented by the container build.
 */
#[CreatesInstancesOf(RetireRequest::class)]
interface RetireRequestFactory
{
    public function create(
        bool $acceptEmbedded,
        bool $cacheCleanedManually,
        bool $ignoreWorkers,
        bool $allowOtherUser,
        ProbeSettings $probeSettings,
    ): RetireRequest;
}
