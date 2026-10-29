<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

final class KeySlotTest extends TestCase
{
    public function testASlotWithAKeyYieldsThatKey(): void
    {
        $raw = KeyMaterial::rawKey();

        $slot = new KeySlot(2, $raw);

        self::assertSame(2, $slot->index());
        self::assertSame($raw, $slot->raw());
        self::assertFalse($slot->isRetired());
        $key = $slot->key(new DirectKeyFactory());
        self::assertNotNull($key);
        self::assertSame($raw, $key->raw());
    }

    public function testAnEntryStartingWithInvalidIsARetiredSlotThatYieldsNoKey(): void
    {
        $slot = new KeySlot(0, KeyMaterial::placeholder());

        self::assertTrue($slot->isRetired());
        self::assertNull($slot->key(new DirectKeyFactory()));
    }

    public function testASlotThatIsNotRetiredButHoldsNoUsableKeyFailsWhenItsKeyIsAskedFor(): void
    {
        $slot = new KeySlot(1, 'too-short');

        $this->expectException(InvalidKey::class);

        $slot->key(new DirectKeyFactory());
    }

    public function testANegativeIndexIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        new KeySlot(-1, KeyMaterial::rawKey());
    }

    public function testAnEntryWithWhitespaceIsRefusedWithoutNamingIt(): void
    {
        $raw = KeyMaterial::rawKey();

        try {
            new KeySlot(0, substr($raw, 0, 10) . ' ' . substr($raw, 11));
            self::fail('An entry with whitespace was accepted.');
        } catch (InvalidKeyRing $refused) {
            self::assertStringNotContainsString(substr($raw, 0, 10), $refused->getMessage());
        }
    }

    public function testAnEmptyEntryIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        new KeySlot(0, '');
    }

    public function testASlotHoldsOnlyTheKeyWithItsExactEntry(): void
    {
        $raw = KeyMaterial::rawKey();
        $slot = new KeySlot(1, $raw);

        self::assertTrue($slot->holds(new Key($raw)));
        self::assertFalse($slot->holds(new Key('base64' . base64_encode($raw))));
        self::assertFalse($slot->holds(new Key(KeyMaterial::rawKey())));
    }

    public function testARetiredSlotHoldsNoKeyEvenWhenThePlaceholderWouldDecode(): void
    {
        $placeholder = KeyMaterial::placeholder();

        self::assertFalse((new KeySlot(0, $placeholder))->holds(new Key($placeholder)));
    }

    public function testDumpingASlotNeverShowsItsEntry(): void
    {
        $raw = KeyMaterial::rawKey();
        $slot = new KeySlot(1, $raw);

        ob_start();
        var_dump($slot);
        $dumped = (string) ob_get_clean();

        self::assertStringNotContainsString($raw, $dumped);
        self::assertStringNotContainsString($raw, print_r($slot, true));
    }

    public function testASlotIsNeverSerialised(): void
    {
        $this->expectException(\LogicException::class);

        serialize(new KeySlot(0, KeyMaterial::rawKey()));
    }
}
