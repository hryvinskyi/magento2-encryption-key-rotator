<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Plaintext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\PlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;

/**
 * Cipher version 3 of the store: ChaCha20-Poly1305 in its IETF variant, through libsodium.
 *
 * The payload is the 12-byte nonce followed by the sealed bytes (ciphertext and 16-byte tag), and the
 * nonce is also the additional authenticated data. Encryption draws a fresh random nonce per value.
 *
 * Decryption returns the bytes exactly as sealed. The store trims what it decrypts; this cipher does
 * not, so a value with leading or trailing whitespace survives a re-encryption unchanged.
 */
final class SodiumCipher implements Cipher
{
    public const VERSION = 3;

    public function __construct(
        private readonly CiphertextFactory $ciphertexts,
        private readonly PlaintextFactory $plaintexts,
    ) {}

    public function supports(int $cipherVersion): bool
    {
        return $cipherVersion === self::VERSION;
    }

    public function decrypt(Ciphertext $ciphertext, Key $key): ?Plaintext
    {
        if (!$this->supports($ciphertext->cipherVersion())) {
            return null;
        }
        $payload = $ciphertext->payloadBytes();
        $nonce = substr($payload, 0, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $sealed = substr($payload, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);

        try {
            $bytes = sodium_crypto_aead_chacha20poly1305_ietf_decrypt($sealed, $nonce, $nonce, $key->bytes());
        } catch (\SodiumException) {
            return null;
        }

        return $bytes === false ? null : $this->plaintexts->create($bytes);
    }

    public function encrypt(Plaintext $plaintext, int $keyIndex, Key $key): Ciphertext
    {
        $nonce = random_bytes(SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $sealed = sodium_crypto_aead_chacha20poly1305_ietf_encrypt($plaintext->bytes(), $nonce, $nonce, $key->bytes());
        $ciphertext = $this->ciphertexts->create($keyIndex, self::VERSION, base64_encode($nonce . $sealed));

        $check = $this->decrypt($ciphertext, $key);
        if ($check === null || !$check->equals($plaintext)) {
            throw new RoundTripFailed(sprintf(
                'A value encrypted under key %s did not decrypt back to the same bytes; it was not returned.',
                $key->fingerprint(),
            ));
        }

        return $ciphertext;
    }
}
