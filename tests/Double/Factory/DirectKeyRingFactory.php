<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectKeyRingFactory implements KeyRingFactory
{
    public function __construct(
        private readonly KeyFactory $keys = new DirectKeyFactory(),
    ) {}

    public function create(array $slots): KeyRing
    {
        return new KeyRing($slots, $this->keys);
    }
}
