<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Crypto;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\InvalidCiphertext;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class CiphertextParserTest extends TestCase
{
    private CiphertextParser $parser;

    protected function setUp(): void
    {
        $this->parser = new CiphertextParser(new DirectCiphertextFactory());
    }

    /**
     * @return iterable<string, array{string, int, int}>
     */
    public static function acceptedValues(): iterable
    {
        $payload = base64_encode(str_repeat("\x01\xfe", 30));
        yield 'index 0' => ['0:3:' . $payload, 0, 3];
        yield 'index 1' => ['1:3:' . $payload, 1, 3];
        yield 'three-digit index' => ['999:3:' . $payload, 999, 3];
        yield 'one padding character' => ['2:3:' . base64_encode('ab'), 2, 3];
        yield 'two padding characters' => ['2:3:' . base64_encode('a'), 2, 3];
        yield 'plus and slash' => ['1:3:' . base64_encode("\xfb\xff\xbf"), 1, 3];
        yield 'another cipher version' => ['1:2:' . $payload, 1, 2];
    }

    #[DataProvider('acceptedValues')]
    public function testAStoredCiphertextIsReadIntoItsPartsAndWrittenBackByteForByte(string $value, int $keyIndex, int $cipherVersion): void
    {
        $ciphertext = $this->parser->parse($value);

        self::assertNotNull($ciphertext);
        self::assertSame($keyIndex, $ciphertext->keyIndex());
        self::assertSame($cipherVersion, $ciphertext->cipherVersion());
        self::assertSame(substr($value, strrpos($value, ':') + 1), $ciphertext->payload());
        self::assertSame($value, $ciphertext->toString());
    }

    public function testThePayloadBytesAreTheDecodedPayload(): void
    {
        $bytes = random_bytes(45);

        $ciphertext = $this->parser->parse('1:3:' . base64_encode($bytes));

        self::assertNotNull($ciphertext);
        self::assertSame($bytes, $ciphertext->payloadBytes());
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function rejectedValues(): iterable
    {
        $payload = base64_encode(random_bytes(40));
        yield 'four parts, the oldest ciphers' => ['1:2:' . base64_encode(random_bytes(16)) . ':' . $payload];
        yield 'missing cipher version' => ['1:' . $payload];
        yield 'payload only' => [$payload];
        yield 'empty' => [''];
        yield 'empty payload' => ['1:3:'];
        yield 'bad base64 character' => ['1:3:' . substr($payload, 0, -4) . 'ab*='];
        yield 'base64 without its padding' => ['1:2:abc'];
        yield 'base64 with non-canonical trailing bits' => ['1:3:abd='];
        yield 'too much padding' => ['1:3:ab==='];
        yield 'trailing newline' => ['1:3:' . $payload . "\n"];
        yield 'trailing space' => ['1:3:' . $payload . ' '];
        yield 'leading space' => [' 1:3:' . $payload];
        yield 'four-digit index' => ['1000:3:' . $payload];
        yield 'leading zero in the index' => ['01:3:' . $payload];
        yield 'two-digit cipher version' => ['1:30:' . $payload];
        yield 'negative index' => ['-1:3:' . $payload];
        yield 'embedded in json' => ['{"token":"1:3:' . $payload . '"}'];
        yield 'url-safe base64' => ['1:3:' . strtr($payload, '+/', '-_') . '-_'];
    }

    #[DataProvider('rejectedValues')]
    public function testAValueThatIsNotExactlyACiphertextIsNotOne(string $value): void
    {
        self::assertNull($this->parser->parse($value));
    }

    public function testACiphertextBuiltFromPartsJoinsThemWithColons(): void
    {
        $payload = base64_encode(random_bytes(30));

        $ciphertext = new Ciphertext(12, 3, $payload);

        self::assertSame('12:3:' . $payload, $ciphertext->toString());
        self::assertTrue($ciphertext->equals(new Ciphertext(12, 3, $payload)));
        self::assertFalse($ciphertext->equals(new Ciphertext(11, 3, $payload)));
    }

    /**
     * @return iterable<string, array{int, int, string}>
     */
    public static function invalidParts(): iterable
    {
        yield 'negative index' => [-1, 3, base64_encode('abc')];
        yield 'index above three digits' => [1000, 3, base64_encode('abc')];
        yield 'negative cipher version' => [1, -1, base64_encode('abc')];
        yield 'two-digit cipher version' => [1, 10, base64_encode('abc')];
        yield 'empty payload' => [1, 3, ''];
        yield 'payload not base64' => [1, 3, 'not base64!'];
        yield 'payload not canonical' => [1, 3, 'abc'];
    }

    #[DataProvider('invalidParts')]
    public function testPartsOutsideTheStoredFormAreRefused(int $keyIndex, int $cipherVersion, string $payload): void
    {
        $this->expectException(InvalidCiphertext::class);

        new Ciphertext($keyIndex, $cipherVersion, $payload);
    }
}
