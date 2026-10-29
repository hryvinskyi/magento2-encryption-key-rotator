<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * The ordered keys of a store, as `crypt/key` lists them. A slot's position is the key index every
 * ciphertext under that key starts with; the last slot is the active key, the one new values are
 * encrypted with.
 *
 * The ring always holds at least one slot, its slots are numbered from 0 without gaps, every slot
 * that is not retired holds a usable key, and the active slot is not retired. Changes never shift an
 * index: a key is appended at the end, a retired slot keeps its place, and only the active slot can
 * be removed, and only when it holds the very key the caller expects.
 *
 * Immutable: every change returns a new ring, created through {@see KeyRingFactory}.
 */
final class KeyRing
{
    /**
     * The highest index a ciphertext can carry.
     */
    public const MAX_INDEX = Ciphertext::MAX_KEY_INDEX;

    /**
     * Length of the placeholder written into a retired slot, the length of an unencoded key, so every
     * consumer of the ring that validates entry lengths keeps accepting it.
     */
    public const PLACEHOLDER_LENGTH = Key::BYTES;

    /**
     * @var list<KeySlot>
     */
    private readonly array $slots;

    /**
     * @var array<int, string> index of every slot that is not retired => fingerprint of its key
     */
    private readonly array $fingerprints;

    /**
     * @param list<KeySlot> $slots the slots in index order
     * @param KeyFactory    $keys  decodes the entries the ring must prove to be keys
     *
     * @throws InvalidKeyRing when the ring is empty, its indices are not 0, 1, 2, … in order, or the
     *                        active slot is retired
     * @throws InvalidKey     when a slot that is not retired does not hold a usable key
     */
    public function __construct(array $slots, KeyFactory $keys)
    {
        $ordered = [];
        $fingerprints = [];
        foreach ($slots as $slot) {
            $position = count($ordered);
            if ($slot->index() !== $position) {
                throw new InvalidKeyRing(sprintf(
                    'Key slots are numbered from 0 without gaps; position %d holds slot %d.',
                    $position,
                    $slot->index(),
                ));
            }
            try {
                $key = $slot->key($keys);
            } catch (InvalidKey $invalid) {
                throw new InvalidKey(sprintf('Key slot %d does not hold a usable key: %s', $position, $invalid->getMessage()), 0, $invalid);
            }
            if ($key !== null) {
                $fingerprints[$position] = $key->fingerprint();
            }
            $ordered[] = $slot;
        }
        if ($ordered === []) {
            throw new InvalidKeyRing('A key ring holds at least one key.');
        }

        $active = count($ordered) - 1;
        if ($ordered[$active]->isRetired()) {
            throw new InvalidKeyRing(sprintf('The active key, slot %d, cannot be a retired slot.', $active));
        }

        $this->slots = $ordered;
        $this->fingerprints = $fingerprints;
    }

    /**
     * The index of the active key: the last slot.
     */
    public function activeIndex(): int
    {
        return count($this->slots) - 1;
    }

    /**
     * The active key, the one new values are encrypted with.
     */
    public function active(KeyFactory $keys): Key
    {
        $index = $this->activeIndex();

        return $this->slots[$index]->key($keys)
            ?? throw new InvalidKeyRing(sprintf('The active key, slot %d, cannot be a retired slot.', $index));
    }

    /**
     * The indices below the active one whose slots still hold a key: the values a rotation moves.
     *
     * @return list<int>
     */
    public function usableOldIndices(): array
    {
        $active = $this->activeIndex();

        return array_values(array_filter(
            array_keys($this->fingerprints),
            static fn(int $index): bool => $index < $active,
        ));
    }

    /**
     * @return KeySlot|null the slot at that index, or null when the ring has none there
     */
    public function slot(int $index): ?KeySlot
    {
        return $this->slots[$index] ?? null;
    }

    /**
     * @return list<KeySlot> every slot, in index order
     */
    public function slots(): array
    {
        return $this->slots;
    }

    /**
     * The ring with the key appended as the new active slot; every existing slot keeps its index.
     *
     * @throws KeyRingChangeRefused when the ring already holds the key, the key's entry would read as a
     *                              retired slot, or the new index would not fit in a ciphertext
     */
    public function appended(Key $key, KeySlotFactory $slots, KeyRingFactory $rings): self
    {
        $index = count($this->slots);
        if ($index > self::MAX_INDEX) {
            throw new KeyRingChangeRefused(sprintf(
                'The key ring is full: a ciphertext cannot carry a key index above %d.',
                self::MAX_INDEX,
            ));
        }
        if (str_starts_with($key->raw(), KeySlot::RETIRED_PREFIX)) {
            throw new KeyRingChangeRefused(sprintf(
                'A key whose entry starts with "%s" would read as a retired slot; it cannot be appended.',
                KeySlot::RETIRED_PREFIX,
            ));
        }
        $holder = array_search($key->fingerprint(), $this->fingerprints, true);
        if ($holder !== false) {
            throw new KeyRingChangeRefused(sprintf(
                'The key %s is already in the ring, in slot %d; a rotation needs a new key.',
                $key->fingerprint(),
                $holder,
            ));
        }

        $next = $this->slots;
        $next[] = $slots->create($index, $key->raw());

        return $rings->create($next);
    }

    /**
     * The ring with each named slot's key replaced by its placeholder, pairing indices and placeholders
     * by position. The slots keep their indices; the active key is never retired.
     *
     * @param list<int>    $indices      the slots to retire
     * @param list<string> $placeholders one placeholder per slot: `invalid` followed by random characters,
     *                                   32 characters in all
     *
     * @throws KeyRingChangeRefused when nothing or the same slot twice is named, the counts differ, a slot
     *                              does not exist, is the active one or is already retired, or a
     *                              placeholder does not have the placeholder's shape
     */
    public function withRetired(array $indices, array $placeholders, KeySlotFactory $slots, KeyRingFactory $rings): self
    {
        if ($indices === []) {
            throw new KeyRingChangeRefused('No slot to retire was named.');
        }
        if (count($indices) !== count($placeholders)) {
            throw new KeyRingChangeRefused(sprintf(
                'Retiring %d slots needs %d placeholders; %d were given.',
                count($indices),
                count($indices),
                count($placeholders),
            ));
        }
        if (count(array_unique($indices)) !== count($indices)) {
            throw new KeyRingChangeRefused('A slot to retire was named more than once.');
        }

        $next = $this->slots;
        foreach ($indices as $position => $index) {
            $this->refuseRetiring($index);
            $placeholder = $placeholders[$position] ?? '';
            if (!$this->isPlaceholder($placeholder)) {
                throw new KeyRingChangeRefused(sprintf(
                    'The placeholder for slot %d must start with "%s" and be exactly %d characters without whitespace.',
                    $index,
                    KeySlot::RETIRED_PREFIX,
                    self::PLACEHOLDER_LENGTH,
                ));
            }
            $next[$index] = $slots->create($index, $placeholder);
        }

        return $rings->create(array_values($next));
    }

    /**
     * The ring with a key put back into a retired slot, used to undo a retirement with the key that was
     * kept when the slot was retired.
     *
     * @param string $raw the kept ring entry of that slot
     *
     * @throws KeyRingChangeRefused when the slot does not exist or is not retired, or the entry is itself
     *                              a placeholder
     * @throws InvalidKey           when the entry is not a usable key
     */
    public function withRestored(int $index, #[\SensitiveParameter] string $raw, KeySlotFactory $slots, KeyRingFactory $rings): self
    {
        $slot = $this->slot($index);
        if ($slot === null) {
            throw new KeyRingChangeRefused(sprintf('The key ring has no slot %d to restore.', $index));
        }
        if (!$slot->isRetired()) {
            throw new KeyRingChangeRefused(sprintf('Slot %d is not retired; only a retired slot can be restored.', $index));
        }
        if (str_starts_with($raw, KeySlot::RETIRED_PREFIX)) {
            throw new KeyRingChangeRefused(sprintf('Slot %d can only be restored with a key, not with a placeholder.', $index));
        }

        $next = $this->slots;
        $next[$index] = $slots->create($index, $raw);

        return $rings->create(array_values($next));
    }

    /**
     * The ring without its active slot, used to undo an append. The slot is removed only when it is the
     * named index and holds exactly the expected key: removing a slot by its position alone could take
     * away a key values still depend on, for instance when an earlier attempt already removed the
     * appended key and the last slot is now the previous active key.
     *
     * @throws KeyRingChangeRefused when the index is not the active one, the active slot holds another key,
     *                              the ring has a single slot, or the slot that would become active is
     *                              retired
     */
    public function withoutSlot(int $index, Key $expected, KeyRingFactory $rings): self
    {
        $active = $this->activeIndex();
        if ($index !== $active) {
            throw new KeyRingChangeRefused(sprintf('Only the active slot, %d, can be removed; slot %d was named.', $active, $index));
        }
        if (!$this->slots[$active]->holds($expected)) {
            throw new KeyRingChangeRefused(sprintf(
                'Slot %d does not hold the key %s; it is left in place.',
                $active,
                $expected->fingerprint(),
            ));
        }
        if ($active === 0) {
            throw new KeyRingChangeRefused('The only slot of a key ring cannot be removed.');
        }
        if ($this->slot($active - 1)?->isRetired() ?? true) {
            throw new KeyRingChangeRefused(sprintf(
                'Removing slot %d would make the retired slot %d the active key.',
                $active,
                $active - 1,
            ));
        }

        return $rings->create(array_slice($this->slots, 0, $active));
    }

    /**
     * The ring as `crypt/key` holds it: the entries joined by a newline, in index order.
     */
    public function export(): string
    {
        return implode("\n", array_map(static fn(KeySlot $slot): string => $slot->raw(), $this->slots));
    }

    /**
     * Identifies the ring without revealing it: the first 16 hex characters of the SHA-256 of
     * {@see export()}.
     */
    public function fingerprint(): string
    {
        return substr(hash('sha256', $this->export()), 0, 16);
    }

    /**
     * @return array{fingerprint: string, slots: list<array{index: int, retired: bool, key?: string}>}
     */
    public function __debugInfo(): array
    {
        $slots = [];
        foreach ($this->slots as $slot) {
            $slots[] = isset($this->fingerprints[$slot->index()])
                ? ['index' => $slot->index(), 'retired' => false, 'key' => $this->fingerprints[$slot->index()]]
                : ['index' => $slot->index(), 'retired' => true];
        }

        return ['fingerprint' => $this->fingerprint(), 'slots' => $slots];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: a ring holds key material, which is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('A key ring cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: a ring is never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('A key ring cannot be unserialised.');
    }

    private function refuseRetiring(int $index): void
    {
        $slot = $this->slot($index);
        if ($slot === null) {
            throw new KeyRingChangeRefused(sprintf('The key ring has no slot %d to retire.', $index));
        }
        if ($index === $this->activeIndex()) {
            throw new KeyRingChangeRefused(sprintf('Slot %d holds the active key, which is never retired.', $index));
        }
        if ($slot->isRetired()) {
            throw new KeyRingChangeRefused(sprintf('Slot %d is already retired.', $index));
        }
    }

    private function isPlaceholder(string $placeholder): bool
    {
        return str_starts_with($placeholder, KeySlot::RETIRED_PREFIX)
            && strlen($placeholder) === self::PLACEHOLDER_LENGTH
            && preg_match('/\s/', $placeholder) === 0;
    }
}
