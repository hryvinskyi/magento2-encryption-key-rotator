<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectKeyFactory implements KeyFactory
{
    public function create(#[\SensitiveParameter] string $raw): Key
    {
        return new Key($raw);
    }
}
