<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Tells whether a stored value decrypts under the key of its index, and if not, why.
 *
 * The checks run in order: the value parses as a ciphertext, the ring (or an extra key given for that
 * index) has a usable key at its index, the cipher reads its version, and it authenticates under that
 * key. The decryption happens in memory only: the plaintext is dropped at once, never returned or kept.
 */
final class CiphertextVerifier
{
    public function __construct(
        private readonly CiphertextParser $parser,
        private readonly Cipher $cipher,
        private readonly KeyFactory $keys,
    ) {}

    /**
     * @param array<int, Key> $extraKeys key index => key that stands in for the ring's slot at that index
     */
    public function verdictOnStored(string $raw, KeyRing $ring, array $extraKeys = []): ValueVerdict
    {
        $ciphertext = $this->parser->parse($raw);

        return $ciphertext === null ? ValueVerdict::Unparsable : $this->verdict($ciphertext, $ring, $extraKeys);
    }

    /**
     * @param array<int, Key> $extraKeys key index => key that stands in for the ring's slot at that index
     */
    public function verdict(Ciphertext $ciphertext, KeyRing $ring, array $extraKeys = []): ValueVerdict
    {
        $key = $extraKeys[$ciphertext->keyIndex()] ?? null;
        if ($key === null) {
            $slot = $ring->slot($ciphertext->keyIndex());
            if ($slot === null) {
                return ValueVerdict::UnknownKey;
            }
            $key = $slot->key($this->keys);
            if ($key === null) {
                return ValueVerdict::RetiredKey;
            }
        }
        if (!$this->cipher->supports($ciphertext->cipherVersion())) {
            return ValueVerdict::UnsupportedCipher;
        }

        return $this->cipher->decrypt($ciphertext, $key) === null ? ValueVerdict::AuthenticationFailed : ValueVerdict::Verified;
    }
}
