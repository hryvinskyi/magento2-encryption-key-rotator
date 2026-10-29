<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;

/**
 * Encrypts and decrypts stored values in the store's own format.
 */
interface Cipher
{
    /**
     * Whether this cipher reads values of that cipher version.
     */
    public function supports(int $cipherVersion): bool;

    /**
     * @return Plaintext|null the exact decrypted bytes, or null when the cipher version is not supported
     *                        or the value does not authenticate under the key
     */
    public function decrypt(Ciphertext $ciphertext, Key $key): ?Plaintext;

    /**
     * Encrypts the plaintext under the key, marking the result with the key's ring index. The result is
     * decrypted again and compared with the plaintext before it is returned.
     *
     * @throws RoundTripFailed when the new ciphertext does not decrypt back to the plaintext
     */
    public function encrypt(Plaintext $plaintext, int $keyIndex, Key $key): Ciphertext;
}
