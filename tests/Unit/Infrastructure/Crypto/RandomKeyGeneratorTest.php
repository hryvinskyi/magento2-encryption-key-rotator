<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Crypto\RandomKeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

final class RandomKeyGeneratorTest extends TestCase
{
    private RandomKeyGenerator $generator;

    protected function setUp(): void
    {
        $this->generator = new RandomKeyGenerator(new DirectKeyFactory());
    }

    public function testAGeneratedKeyIsThirtyTwoRandomBytesWrittenAsBase64(): void
    {
        $key = $this->generator->generate();

        self::assertMatchesRegularExpression('~^base64[A-Za-z0-9+/]{43}=$~', $key->raw());
        self::assertSame(32, strlen($key->bytes()));
        self::assertSame(base64_decode(substr($key->raw(), 6), true), $key->bytes());
    }

    public function testEveryGeneratedKeyIsNew(): void
    {
        self::assertFalse($this->generator->generate()->equals($this->generator->generate()));
    }

    public function testAPlaceholderIsInvalidFollowedByTwentyFiveAlphanumericCharacters(): void
    {
        $placeholder = $this->generator->placeholder();

        self::assertMatchesRegularExpression('/^invalid[A-Za-z0-9]{25}$/D', $placeholder);
        self::assertTrue((new KeySlot(0, $placeholder))->isRetired());
        self::assertNotSame($placeholder, $this->generator->placeholder());
    }

    public function testAKeyRingAcceptsTheGeneratedKeyAndPlaceholder(): void
    {
        $slots = new DirectKeySlotFactory();
        $rings = new DirectKeyRingFactory();
        $ring = $rings->create([new KeySlot(0, KeyMaterial::rawKey())]);
        $key = $this->generator->generate();

        $retired = $ring->appended($key, $slots, $rings)->withRetired([0], [$this->generator->placeholder()], $slots, $rings);

        self::assertSame(1, $retired->activeIndex());
        self::assertTrue($retired->active(new DirectKeyFactory())->equals($key));
        self::assertSame([], $retired->usableOldIndices());
    }
}
