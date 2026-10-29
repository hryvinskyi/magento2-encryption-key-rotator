<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectKeySlotFactory implements KeySlotFactory
{
    public function create(int $index, #[\SensitiveParameter] string $raw): KeySlot
    {
        return new KeySlot($index, $raw);
    }
}
