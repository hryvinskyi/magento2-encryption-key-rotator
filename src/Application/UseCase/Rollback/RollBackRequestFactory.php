<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RollBackRequest} values; implemented by the container build.
 */
#[CreatesInstancesOf(RollBackRequest::class)]
interface RollBackRequestFactory
{
    public function create(bool $ignoreWorkers, bool $allowOtherUser, ProbeSettings $probeSettings, bool $acceptEmbedded): RollBackRequest;
}
