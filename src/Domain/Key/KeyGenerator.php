<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * Draws the new material a rotation writes into the ring.
 */
interface KeyGenerator
{
    /**
     * A new random key, in the encoding the store itself writes for new keys.
     */
    public function generate(): Key;

    /**
     * A new placeholder for a retired slot: `invalid` followed by random alphanumeric characters,
     * {@see KeyRing::PLACEHOLDER_LENGTH} characters in all.
     */
    public function placeholder(): string;
}
