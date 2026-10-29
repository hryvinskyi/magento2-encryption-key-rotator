<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequestFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRotateRequestFactory implements RotateRequestFactory
{
    public function create(
        bool $dryRun,
        #[\SensitiveParameter]
        ?string $rawKey,
        int $batchSize,
        bool $ignoreWorkers,
        bool $allowOtherUser,
        ProbeSettings $probeSettings,
    ): RotateRequest {
        return new RotateRequest($dryRun, $rawKey, $batchSize, $ignoreWorkers, $allowOtherUser, $probeSettings);
    }
}
