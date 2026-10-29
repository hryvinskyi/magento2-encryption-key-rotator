<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

/**
 * A decrypted value, kept exactly: no byte is trimmed, converted or normalised, so a value that is
 * decrypted and encrypted again comes back byte for byte.
 *
 * The value never prints itself: dumping it shows a redaction marker, and serialising it fails.
 * Created through {@see PlaintextFactory}.
 */
final class Plaintext
{
    public function __construct(
        #[\SensitiveParameter]
        private readonly string $bytes,
    ) {}

    public function bytes(): string
    {
        return $this->bytes;
    }

    public function equals(self $other): bool
    {
        return hash_equals($this->bytes, $other->bytes);
    }

    /**
     * @return array{bytes: string}
     */
    public function __debugInfo(): array
    {
        return ['bytes' => '[redacted]'];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: a plaintext is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('A plaintext cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: a plaintext is never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A plaintext cannot be unserialised.');
    }
}
