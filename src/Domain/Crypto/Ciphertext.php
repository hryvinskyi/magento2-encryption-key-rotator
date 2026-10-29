<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

/**
 * A stored encrypted value, `<key index>:<cipher version>:<payload>`: the slot of the key ring it was
 * encrypted under, the cipher that wrote it, and the base64 payload.
 *
 * The parts are kept in the exact form the store writes: the key index has no leading zero and fits
 * three digits, the cipher version is one digit, and the payload is canonical, padded base64. So
 * {@see toString()} gives back, byte for byte, the value the parts were read from.
 *
 * Created through {@see CiphertextFactory}; read from a stored string by {@see CiphertextParser}.
 */
final class Ciphertext
{
    public const MAX_KEY_INDEX = 999;
    public const MAX_CIPHER_VERSION = 9;

    /**
     * @param int    $keyIndex      the key ring slot the value is encrypted under
     * @param int    $cipherVersion the cipher that wrote it
     * @param string $payload       the canonical base64 of what the cipher wrote
     *
     * @throws InvalidCiphertext when a part is out of range or the payload is not canonical base64
     */
    public function __construct(
        private readonly int $keyIndex,
        private readonly int $cipherVersion,
        private readonly string $payload,
    ) {
        if ($keyIndex < 0 || $keyIndex > self::MAX_KEY_INDEX) {
            throw new InvalidCiphertext(sprintf('A ciphertext key index lies between 0 and %d; %d was given.', self::MAX_KEY_INDEX, $keyIndex));
        }
        if ($cipherVersion < 0 || $cipherVersion > self::MAX_CIPHER_VERSION) {
            throw new InvalidCiphertext(sprintf('A cipher version is one digit; %d was given.', $cipherVersion));
        }
        $bytes = $payload === '' ? false : base64_decode($payload, true);
        if ($bytes === false || base64_encode($bytes) !== $payload) {
            throw new InvalidCiphertext('A ciphertext payload must be non-empty, canonical base64.');
        }
    }

    public function keyIndex(): int
    {
        return $this->keyIndex;
    }

    public function cipherVersion(): int
    {
        return $this->cipherVersion;
    }

    /**
     * The payload as stored: base64.
     */
    public function payload(): string
    {
        return $this->payload;
    }

    /**
     * The payload decoded: what the cipher wrote.
     */
    public function payloadBytes(): string
    {
        return (string) base64_decode($this->payload, true);
    }

    /**
     * The stored form, `<key index>:<cipher version>:<payload>`.
     */
    public function toString(): string
    {
        return $this->keyIndex . ':' . $this->cipherVersion . ':' . $this->payload;
    }

    public function equals(self $other): bool
    {
        return $this->toString() === $other->toString();
    }
}
