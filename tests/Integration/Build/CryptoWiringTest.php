<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\SodiumCipher;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

/**
 * The key ring and the cipher work through the generated factories and the bindings of the real
 * container, not only through test doubles.
 *
 * Each test runs in its own process: another test of the suite may already have loaded the generated
 * factory classes from its own build directory, and a class cannot be loaded twice.
 */
final class CryptoWiringTest extends TestCase
{
    private CryptoServices $services;

    protected function setUp(): void
    {
        $this->services = CryptoServices::shared();
    }

    public function testTheContainerParsesARingAppendsAGeneratedKeyAndRetiresTheOldOne(): void
    {
        $ring = $this->services->ringParser()->parse(KeyMaterial::placeholder() . "\n" . KeyMaterial::rawKey());
        $generator = $this->services->keyGenerator();
        $new = $generator->generate();

        $rotated = $ring->appended($new, $this->services->slots(), $this->services->rings());
        $retired = $rotated->withRetired([1], [$generator->placeholder()], $this->services->slots(), $this->services->rings());

        self::assertSame([1], $rotated->usableOldIndices());
        self::assertSame(2, $retired->activeIndex());
        self::assertSame([], $retired->usableOldIndices());
        self::assertTrue($retired->active($this->services->keys())->equals($new));
        self::assertSame($retired->export(), $this->services->ringParser()->parse($retired->export())->export());
    }

    public function testTheGeneratedRingFactoryRefusesASlotThatHoldsNoKey(): void
    {
        $this->expectException(InvalidKey::class);

        $this->services->ringParser()->parse('not-a-key ' . KeyMaterial::rawKey());
    }

    public function testTheBoundCipherEncryptsWhatTheParserReadsBack(): void
    {
        $cipher = $this->services->cipher();
        $key = $this->services->keyGenerator()->generate();
        $plaintext = $this->services->plaintexts()->create(" exact bytes \n");

        $stored = $cipher->encrypt($plaintext, 7, $key)->toString();
        $read = $this->services->ciphertextParser()->parse($stored);

        self::assertInstanceOf(SodiumCipher::class, $cipher);
        self::assertNotNull($read);
        self::assertSame($stored, $read->toString());
        self::assertSame(7, $read->keyIndex());
        self::assertSame(" exact bytes \n", $cipher->decrypt($read, $key)?->bytes());
    }
}
