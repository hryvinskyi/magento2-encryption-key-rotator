<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectPurgeRequestFactory implements PurgeRequestFactory
{
    public function create(?RunId $runId, bool $acceptLoss): PurgeRequest
    {
        return new PurgeRequest($runId, $acceptLoss);
    }
}
