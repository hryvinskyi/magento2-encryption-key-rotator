<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectCiphertextFactory implements CiphertextFactory
{
    public function create(int $keyIndex, int $cipherVersion, string $payload): Ciphertext
    {
        return new Ciphertext($keyIndex, $cipherVersion, $payload);
    }
}
