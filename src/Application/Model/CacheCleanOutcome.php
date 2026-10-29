<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Whether the store's configuration cache was cleaned, with a reason for the operator when it was not.
 * The reason has passed through the secret redactor.
 *
 * Created through {@see CacheCleanOutcomeFactory}.
 */
final class CacheCleanOutcome
{
    public function __construct(
        private readonly bool $cleaned,
        private readonly string $reason,
    ) {}

    public function cleaned(): bool
    {
        return $this->cleaned;
    }

    public function reason(): string
    {
        return $this->reason;
    }
}
