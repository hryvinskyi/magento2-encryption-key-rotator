<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * What the operator asked a purge to do:
 * - the run to purge, or null for the run the state directory holds now (the unfinished one, else the one
 *   started last);
 * - whether values that only the run's kept keys still decrypt may become unreadable for good; the loss
 *   is recorded and printed with its counts.
 *
 * Created through {@see PurgeRequestFactory}.
 */
final class PurgeRequest
{
    public function __construct(
        private readonly ?RunId $runId,
        private readonly bool $acceptLoss,
    ) {}

    public function runId(): ?RunId
    {
        return $this->runId;
    }

    public function acceptsLoss(): bool
    {
        return $this->acceptLoss;
    }
}
