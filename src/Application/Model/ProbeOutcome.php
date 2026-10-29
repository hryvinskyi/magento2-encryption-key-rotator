<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What a web tier probe found, with a reason for the operator. The reason never carries a key, a
 * token or a response body: only what happened and what to do about it.
 *
 * Created through {@see ProbeOutcomeFactory}.
 */
final class ProbeOutcome
{
    public function __construct(
        private readonly ProbeStatus $status,
        private readonly string $reason,
    ) {}

    public function status(): ProbeStatus
    {
        return $this->status;
    }

    public function matches(): bool
    {
        return $this->status === ProbeStatus::Matches;
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
