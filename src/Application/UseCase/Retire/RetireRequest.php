<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;

/**
 * What the operator asked a retirement of the old keys to do:
 * - whether values embedded inside larger values, and columns whose scan the database cut short, are
 *   acknowledged: their keys are retired although the scan could not judge them;
 * - whether the configuration cache was cleaned by hand, standing in for a clean the tool could not do;
 * - whether processes that may hold an earlier key ring may keep running, and whether the tool may run as
 *   another user than the owner of the deployment configuration;
 * - how the web tier is asked which ring it holds, the skip included.
 *
 * Every flag that waives a check is recorded on the run when it does waive one. Created through
 * {@see RetireRequestFactory}.
 */
final class RetireRequest
{
    public function __construct(
        private readonly bool $acceptEmbedded,
        private readonly bool $cacheCleanedManually,
        private readonly bool $ignoreWorkers,
        private readonly bool $allowOtherUser,
        private readonly ProbeSettings $probeSettings,
    ) {}

    public function acceptsEmbedded(): bool
    {
        return $this->acceptEmbedded;
    }

    public function cacheCleanedManually(): bool
    {
        return $this->cacheCleanedManually;
    }

    public function ignoresWorkers(): bool
    {
        return $this->ignoreWorkers;
    }

    public function allowsOtherUser(): bool
    {
        return $this->allowOtherUser;
    }

    public function probeSettings(): ProbeSettings
    {
        return $this->probeSettings;
    }
}
