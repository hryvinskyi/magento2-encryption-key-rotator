<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;

/**
 * What the operator asked a rollback to do:
 * - whether processes that may hold an earlier key ring may keep running, and whether the tool may run as
 *   another user than the owner of the deployment configuration, both recorded on the run when they
 *   waive something;
 * - how the web tier is asked which ring it holds, the skip included;
 * - whether the new key may be removed although values hold a ciphertext inside a larger value, or a
 *   column's scan was cut short (recorded on the run); it never waives whole values that remain under
 *   the new key.
 *
 * Created through {@see RollBackRequestFactory}.
 */
final class RollBackRequest
{
    public function __construct(
        private readonly bool $ignoreWorkers,
        private readonly bool $allowOtherUser,
        private readonly ProbeSettings $probeSettings,
        private readonly bool $acceptEmbedded = false,
    ) {}

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

    public function acceptsEmbedded(): bool
    {
        return $this->acceptEmbedded;
    }
}
