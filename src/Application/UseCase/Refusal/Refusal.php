<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal;

/**
 * One reason a writing command stopped, with a sentence for the operator. The sentence names
 * fingerprints, paths, user ids and process descriptions, never a key, a plaintext or a password.
 *
 * Created through {@see RefusalFactory}.
 */
final class Refusal
{
    public function __construct(
        private readonly RefusalReason $reason,
        private readonly string $message,
    ) {}

    public function reason(): RefusalReason
    {
        return $this->reason;
    }

    public function message(): string
    {
        return $this->message;
    }
}
