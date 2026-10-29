<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Plaintext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\PlaintextFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectPlaintextFactory implements PlaintextFactory
{
    public function create(#[\SensitiveParameter] string $bytes): Plaintext
    {
        return new Plaintext($bytes);
    }
}
