<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * One encryption key: the entry exactly as the key ring writes it, and the 32 bytes it stands for.
 *
 * An entry that starts with `base64` holds the key base64-encoded after that prefix; any other entry is
 * the key itself. A key is valid only when its entry is not empty, holds no whitespace and stands for
 * exactly 32 bytes, so an instance always holds a usable key.
 *
 * The key never prints itself: dumping it shows only its fingerprint, and serialising it fails.
 * Created through {@see KeyFactory}.
 */
final class Key
{
    public const BASE64_PREFIX = 'base64';
    public const BYTES = 32;

    private readonly string $raw;
    private readonly string $bytes;

    /**
     * @param string $raw the ring entry
     *
     * @throws InvalidKey when the entry is empty, holds whitespace or does not stand for 32 bytes
     */
    public function __construct(#[\SensitiveParameter] string $raw)
    {
        if ($raw === '') {
            throw new InvalidKey('An encryption key cannot be empty.');
        }
        if (preg_match('/\s/', $raw) === 1) {
            throw new InvalidKey('An encryption key cannot contain whitespace.');
        }
        $bytes = $this->decode($raw);
        if ($bytes === null) {
            throw new InvalidKey(sprintf('An encryption key that starts with "%s" must be valid base64 after the prefix.', self::BASE64_PREFIX));
        }
        if (strlen($bytes) !== self::BYTES) {
            throw new InvalidKey(sprintf('An encryption key must stand for exactly %d bytes; this one stands for %d.', self::BYTES, strlen($bytes)));
        }

        $this->raw = $raw;
        $this->bytes = $bytes;
    }

    /**
     * The entry exactly as the key ring writes it.
     */
    public function raw(): string
    {
        return $this->raw;
    }

    /**
     * The 32 key bytes the cipher uses.
     */
    public function bytes(): string
    {
        return $this->bytes;
    }

    /**
     * Identifies the key in output without revealing it: the first 16 hex characters of the SHA-256 of
     * its bytes.
     */
    public function fingerprint(): string
    {
        return substr(hash('sha256', $this->bytes), 0, 16);
    }

    /**
     * Two keys are equal when their ring entries are identical, byte for byte.
     */
    public function equals(self $other): bool
    {
        return hash_equals($this->raw, $other->raw);
    }

    /**
     * @return array{fingerprint: string}
     */
    public function __debugInfo(): array
    {
        return ['fingerprint' => $this->fingerprint()];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: key material is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('An encryption key cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: a key is never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('An encryption key cannot be unserialised.');
    }

    /**
     * @return string|null the key bytes, or null when a base64 entry does not decode
     */
    private function decode(#[\SensitiveParameter] string $raw): ?string
    {
        if (!str_starts_with($raw, self::BASE64_PREFIX)) {
            return $raw;
        }
        $bytes = base64_decode(substr($raw, strlen(self::BASE64_PREFIX)), true);

        return $bytes === false ? null : $bytes;
    }
}
