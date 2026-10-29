<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates key rings from their slots; implemented by the container build. Turning a `crypt/key` string
 * into slots is {@see KeyRingParser}'s.
 */
#[CreatesInstancesOf(KeyRing::class)]
interface KeyRingFactory
{
    /**
     * @param list<KeySlot> $slots the slots in index order
     *
     * @throws InvalidKeyRing when the slots do not form a ring
     * @throws InvalidKey     when a slot that is not retired does not hold a usable key
     */
    public function create(array $slots): KeyRing;
}
