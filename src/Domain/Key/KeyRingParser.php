<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * Reads a `crypt/key` value into a key ring the way the store reads it: surrounding whitespace is
 * dropped and every run of whitespace separates two entries, the first entry being slot 0.
 */
final class KeyRingParser
{
    public function __construct(
        private readonly KeySlotFactory $slots,
        private readonly KeyRingFactory $rings,
    ) {}

    /**
     * @param string $cryptKey the `crypt/key` value
     *
     * @throws InvalidKeyRing when the value holds no entry or does not form a ring
     * @throws InvalidKey     when an entry that is not a placeholder is not a usable key
     */
    public function parse(#[\SensitiveParameter] string $cryptKey): KeyRing
    {
        $trimmed = trim($cryptKey);
        if ($trimmed === '') {
            throw new InvalidKeyRing('The key ring is empty: crypt/key holds no key.');
        }
        $entries = preg_split('/\s+/', $trimmed);
        if ($entries === false) {
            throw new InvalidKeyRing('The key ring cannot be split into its entries.');
        }

        $slots = [];
        foreach ($entries as $index => $entry) {
            $slots[] = $this->slots->create($index, $entry);
        }

        return $this->rings->create($slots);
    }
}
