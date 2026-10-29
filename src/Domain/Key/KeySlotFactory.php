<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates key slots; implemented by the container build.
 */
#[CreatesInstancesOf(KeySlot::class)]
interface KeySlotFactory
{
    /**
     * @param int    $index the position in the ring, from 0
     * @param string $raw   the entry written at that position
     *
     * @throws InvalidKeyRing when the index is negative or the entry cannot be written into a ring
     */
    public function create(int $index, #[\SensitiveParameter] string $raw): KeySlot;
}
