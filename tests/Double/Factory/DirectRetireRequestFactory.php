<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequestFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRetireRequestFactory implements RetireRequestFactory
{
    public function create(
        bool $acceptEmbedded,
        bool $cacheCleanedManually,
        bool $ignoreWorkers,
        bool $allowOtherUser,
        ProbeSettings $probeSettings,
    ): RetireRequest {
        return new RetireRequest($acceptEmbedded, $cacheCleanedManually, $ignoreWorkers, $allowOtherUser, $probeSettings);
    }
}
