<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Plaintext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\PlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\SodiumCipher;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPlaintextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class SodiumCipherTest extends TestCase
{
    private SodiumCipher $cipher;
    private Key $key;

    protected function setUp(): void
    {
        $this->cipher = new SodiumCipher(new DirectCiphertextFactory(), new DirectPlaintextFactory());
        $this->key = new Key(KeyMaterial::base64Key());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function plaintexts(): iterable
    {
        yield 'plain text' => ['api-secret-value'];
        yield 'leading and trailing whitespace' => ["  padded value\n\t "];
        yield 'only whitespace' => [" \n "];
        yield 'multibyte' => ['Пароль — 密码 — كلمة السر — 🔑'];
        yield 'binary with a zero byte' => ["\x00\xff\x10binary\x00"];
        yield 'empty' => [''];
        yield 'long' => [str_repeat('0123456789abcdef', 512)];
    }

    #[DataProvider('plaintexts')]
    public function testAValueRoundTripsByteForByte(string $bytes): void
    {
        $plaintext = new Plaintext($bytes);

        $ciphertext = $this->cipher->encrypt($plaintext, 4, $this->key);
        $decrypted = $this->cipher->decrypt($ciphertext, $this->key);

        self::assertSame(4, $ciphertext->keyIndex());
        self::assertSame(3, $ciphertext->cipherVersion());
        self::assertNotNull($decrypted);
        self::assertSame($bytes, $decrypted->bytes());
    }

    public function testThePayloadIsTheNonceFollowedByTheSealedValueWithTheNonceAsAssociatedData(): void
    {
        $ciphertext = $this->cipher->encrypt(new Plaintext('value'), 1, $this->key);

        $payload = $ciphertext->payloadBytes();
        $nonce = substr($payload, 0, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);
        $sealed = substr($payload, SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES);

        self::assertSame(
            SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_NPUBBYTES + strlen('value') + SODIUM_CRYPTO_AEAD_CHACHA20POLY1305_IETF_ABYTES,
            strlen($payload),
        );
        self::assertSame('value', sodium_crypto_aead_chacha20poly1305_ietf_decrypt($sealed, $nonce, $nonce, $this->key->bytes()));
        self::assertFalse(sodium_crypto_aead_chacha20poly1305_ietf_decrypt($sealed, '', $nonce, $this->key->bytes()));
    }

    public function testEveryEncryptionDrawsANewNonce(): void
    {
        $plaintext = new Plaintext('same value');

        self::assertNotSame(
            $this->cipher->encrypt($plaintext, 1, $this->key)->toString(),
            $this->cipher->encrypt($plaintext, 1, $this->key)->toString(),
        );
    }

    public function testAValueUnderAnotherKeyDoesNotDecrypt(): void
    {
        $ciphertext = $this->cipher->encrypt(new Plaintext('value'), 1, $this->key);

        self::assertNull($this->cipher->decrypt($ciphertext, new Key(KeyMaterial::rawKey())));
    }

    public function testATamperedPayloadDoesNotDecrypt(): void
    {
        $ciphertext = $this->cipher->encrypt(new Plaintext('value'), 1, $this->key);
        $payload = $ciphertext->payloadBytes();
        $last = strlen($payload) - 1;
        $payload[$last] = chr(ord($payload[$last]) ^ 0x01);

        self::assertNull($this->cipher->decrypt(new Ciphertext(1, 3, base64_encode($payload)), $this->key));
    }

    public function testATamperedNonceDoesNotDecrypt(): void
    {
        $ciphertext = $this->cipher->encrypt(new Plaintext('value'), 1, $this->key);
        $payload = $ciphertext->payloadBytes();
        $payload[0] = chr(ord($payload[0]) ^ 0x80);

        self::assertNull($this->cipher->decrypt(new Ciphertext(1, 3, base64_encode($payload)), $this->key));
    }

    public function testAPayloadShorterThanANonceDoesNotDecrypt(): void
    {
        self::assertNull($this->cipher->decrypt(new Ciphertext(1, 3, base64_encode('short')), $this->key));
    }

    public function testAPayloadWithANonceButNoTagDoesNotDecrypt(): void
    {
        self::assertNull($this->cipher->decrypt(new Ciphertext(1, 3, base64_encode(random_bytes(20))), $this->key));
    }

    public function testOnlyCipherVersionThreeIsSupported(): void
    {
        self::assertTrue($this->cipher->supports(3));
        self::assertFalse($this->cipher->supports(2));
        self::assertFalse($this->cipher->supports(1));
        self::assertFalse($this->cipher->supports(0));
        self::assertFalse($this->cipher->supports(4));
    }

    public function testAValueOfAnUnsupportedCipherVersionIsNotDecrypted(): void
    {
        $ciphertext = $this->cipher->encrypt(new Plaintext('value'), 1, $this->key);

        self::assertNull($this->cipher->decrypt(new Ciphertext(1, 2, $ciphertext->payload()), $this->key));
    }

    public function testAnEncryptionThatDoesNotDecryptBackToItsPlaintextIsRefused(): void
    {
        $corrupting = new class implements PlaintextFactory {
            public function create(#[\SensitiveParameter] string $bytes): Plaintext
            {
                return new Plaintext($bytes . '?');
            }
        };
        $cipher = new SodiumCipher(new DirectCiphertextFactory(), $corrupting);

        try {
            $cipher->encrypt(new Plaintext('secret value'), 1, $this->key);
            self::fail('A ciphertext that does not round-trip was returned.');
        } catch (RoundTripFailed $refused) {
            self::assertStringNotContainsString('secret value', $refused->getMessage());
            self::assertStringNotContainsString($this->key->raw(), $refused->getMessage());
            self::assertStringContainsString($this->key->fingerprint(), $refused->getMessage());
        }
    }
}
