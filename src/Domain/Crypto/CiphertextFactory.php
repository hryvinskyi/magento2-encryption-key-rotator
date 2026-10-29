<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates ciphertexts from their parts; implemented by the container build. Reading one from a stored
 * string is {@see CiphertextParser}'s.
 */
#[CreatesInstancesOf(Ciphertext::class)]
interface CiphertextFactory
{
    /**
     * @param int    $keyIndex      the key ring slot the value is encrypted under
     * @param int    $cipherVersion the cipher that wrote it
     * @param string $payload       the canonical base64 of what the cipher wrote
     *
     * @throws InvalidCiphertext when a part is out of range or the payload is not canonical base64
     */
    public function create(int $keyIndex, int $cipherVersion, string $payload): Ciphertext;
}
