<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * One position of the key ring: its index, which every ciphertext under it carries, and the entry
 * written there.
 *
 * An entry that starts with `invalid` is a placeholder: the slot is retired, it yields no key, and its
 * index stays taken so no other slot moves. Any other entry is meant to be a key; whether it is one is
 * the ring's to check.
 *
 * Dumping a slot shows its index and whether it is retired, never its entry; serialising it fails.
 * Created through {@see KeySlotFactory}.
 */
final class KeySlot
{
    public const RETIRED_PREFIX = 'invalid';

    /**
     * @param int    $index the position in the ring, from 0
     * @param string $raw   the entry written at that position
     *
     * @throws InvalidKeyRing when the index is negative, or the entry is empty or holds whitespace
     *                        (the ring separates its entries by whitespace)
     */
    public function __construct(
        private readonly int $index,
        #[\SensitiveParameter]
        private readonly string $raw,
    ) {
        if ($index < 0) {
            throw new InvalidKeyRing(sprintf('A key slot index cannot be negative; %d was given.', $index));
        }
        if ($raw === '' || preg_match('/\s/', $raw) === 1) {
            throw new InvalidKeyRing(sprintf('Key slot %d needs an entry without whitespace.', $index));
        }
    }

    public function index(): int
    {
        return $this->index;
    }

    /**
     * The entry exactly as the ring writes it: a key, or the placeholder of a retired slot.
     */
    public function raw(): string
    {
        return $this->raw;
    }

    public function isRetired(): bool
    {
        return str_starts_with($this->raw, self::RETIRED_PREFIX);
    }

    /**
     * @return Key|null the slot's key, or null when the slot is retired
     *
     * @throws InvalidKey when the slot is not retired and its entry is not a usable key
     */
    public function key(KeyFactory $keys): ?Key
    {
        return $this->isRetired() ? null : $keys->create($this->raw);
    }

    /**
     * Whether this slot holds exactly that key: it is not retired and its entry is the key's entry.
     */
    public function holds(Key $key): bool
    {
        return !$this->isRetired() && hash_equals($this->raw, $key->raw());
    }

    /**
     * @return array{index: int, retired: bool}
     */
    public function __debugInfo(): array
    {
        return ['index' => $this->index, 'retired' => $this->isRetired()];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: a slot entry may be key material, which is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('A key slot cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: a slot is never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A key slot cannot be unserialised.');
    }
}
