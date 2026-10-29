<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;

/**
 * Draws keys and placeholders from the operating system's cryptographically secure generator.
 *
 * A key is 32 random bytes written as `base64` followed by their base64, the form the store itself
 * writes for a key it generates. A placeholder is `invalid` followed by random alphanumeric characters.
 */
final class RandomKeyGenerator implements KeyGenerator
{
    private const PLACEHOLDER_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789';

    public function __construct(
        private readonly KeyFactory $keys,
    ) {}

    public function generate(): Key
    {
        return $this->keys->create(Key::BASE64_PREFIX . base64_encode(random_bytes(Key::BYTES)));
    }

    public function placeholder(): string
    {
        $placeholder = KeySlot::RETIRED_PREFIX;
        $last = strlen(self::PLACEHOLDER_ALPHABET) - 1;
        while (strlen($placeholder) < KeyRing::PLACEHOLDER_LENGTH) {
            $placeholder .= self::PLACEHOLDER_ALPHABET[random_int(0, $last)];
        }

        return $placeholder;
    }
}
