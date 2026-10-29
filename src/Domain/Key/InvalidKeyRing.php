<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * A key ring, or one of its slots, that breaks the ring's shape: no slot, a gap or a disorder in the
 * slot indices, a retired active slot, or an entry that cannot be written into a ring.
 */
final class InvalidKeyRing extends \InvalidArgumentException {}
