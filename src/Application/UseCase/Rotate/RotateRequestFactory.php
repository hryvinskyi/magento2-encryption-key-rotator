<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RotateRequest} values; implemented by the container build.
 */
#[CreatesInstancesOf(RotateRequest::class)]
interface RotateRequestFactory
{
    /**
     * @throws InvalidValue when the batch size is below 1 or the key entry is empty
     */
    public function create(
        bool $dryRun,
        #[\SensitiveParameter]
        ?string $rawKey,
        int $batchSize,
        bool $ignoreWorkers,
        bool $allowOtherUser,
        ProbeSettings $probeSettings,
    ): RotateRequest;
}
