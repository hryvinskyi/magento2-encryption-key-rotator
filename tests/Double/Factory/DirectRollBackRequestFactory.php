<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequestFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRollBackRequestFactory implements RollBackRequestFactory
{
    public function create(bool $ignoreWorkers, bool $allowOtherUser, ProbeSettings $probeSettings, bool $acceptEmbedded): RollBackRequest
    {
        return new RollBackRequest($ignoreWorkers, $allowOtherUser, $probeSettings, $acceptEmbedded);
    }
}
