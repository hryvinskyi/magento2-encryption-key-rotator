<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyRingParserTest extends TestCase
{
    private KeyRingParser $parser;

    protected function setUp(): void
    {
        $this->parser = new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory());
    }

    public function testASingleKeyIsARingWhoseOnlySlotIsActive(): void
    {
        $raw = KeyMaterial::rawKey();

        $ring = $this->parser->parse($raw);

        self::assertSame(0, $ring->activeIndex());
        self::assertSame($raw, $ring->active(new DirectKeyFactory())->raw());
        self::assertSame([], $ring->usableOldIndices());
    }

    public function testARetiredSlotZeroFollowedByAThirtyTwoCharacterKey(): void
    {
        $placeholder = KeyMaterial::placeholder();
        $active = KeyMaterial::rawKey();

        $ring = $this->parser->parse($placeholder . "\n" . $active);

        self::assertSame(1, $ring->activeIndex());
        self::assertSame($active, $ring->active(new DirectKeyFactory())->raw());
        $slotZero = $ring->slot(0);
        self::assertNotNull($slotZero);
        self::assertTrue($slotZero->isRetired());
        self::assertSame($placeholder, $slotZero->raw());
        self::assertSame([], $ring->usableOldIndices());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function separators(): iterable
    {
        yield 'newline' => ["\n"];
        yield 'carriage return and newline' => ["\r\n"];
        yield 'space' => [' '];
        yield 'tab' => ["\t"];
        yield 'several blank lines' => ["\n\n \n"];
    }

    #[DataProvider('separators')]
    public function testAnyRunOfWhitespaceSeparatesEntriesAndSurroundingWhitespaceIsDropped(string $separator): void
    {
        $first = KeyMaterial::base64Key();
        $second = KeyMaterial::rawKey();

        $ring = $this->parser->parse(" \n" . $first . $separator . $second . "\n\t");

        self::assertSame($first . "\n" . $second, $ring->export());
        self::assertSame([0], $ring->usableOldIndices());
    }

    public function testAnExportedRingParsesBackToTheSameRing(): void
    {
        $ring = $this->parser->parse(implode(' ', [
            KeyMaterial::placeholder(),
            KeyMaterial::rawKey(),
            KeyMaterial::base64Key(),
        ]));

        $again = $this->parser->parse($ring->export());

        self::assertSame($ring->export(), $again->export());
        self::assertSame($ring->fingerprint(), $again->fingerprint());
    }

    public function testAnEmptyValueIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);

        $this->parser->parse(" \n\t ");
    }

    public function testAnEntryThatIsNeitherAKeyNorAPlaceholderIsRefusedWithItsSlotNamed(): void
    {
        $this->expectException(InvalidKey::class);
        $this->expectExceptionMessage('Key slot 1');

        $this->parser->parse(KeyMaterial::rawKey() . "\n" . 'not-a-key');
    }

    public function testARingWhoseLastSlotIsRetiredIsRefused(): void
    {
        $this->expectException(InvalidKeyRing::class);
        $this->expectExceptionMessage('active key, slot 1');

        $this->parser->parse(KeyMaterial::rawKey() . "\n" . KeyMaterial::placeholder());
    }
}
