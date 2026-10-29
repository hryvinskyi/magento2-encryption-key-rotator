<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates plaintexts; implemented by the container build.
 */
#[CreatesInstancesOf(Plaintext::class)]
interface PlaintextFactory
{
    public function create(#[\SensitiveParameter] string $bytes): Plaintext;
}
