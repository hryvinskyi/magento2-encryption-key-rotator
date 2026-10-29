<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class KeyTest extends TestCase
{
    private const RAW_KEY = 'q7Hf2LmZ0pXw9Rt4Vb6Nc1Ks8Dj3Ga5E';

    public function testAThirtyTwoCharacterEntryIsItsOwnBytes(): void
    {
        $key = new Key(self::RAW_KEY);

        self::assertSame(self::RAW_KEY, $key->raw());
        self::assertSame(self::RAW_KEY, $key->bytes());
    }

    public function testABase64EntryIsDecodedAfterItsPrefix(): void
    {
        $bytes = random_bytes(32);
        $raw = 'base64' . base64_encode($bytes);

        $key = new Key($raw);

        self::assertSame($raw, $key->raw());
        self::assertSame($bytes, $key->bytes());
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function unusableEntries(): iterable
    {
        yield 'empty' => ['', 'empty'];
        yield 'leading space' => [' ' . substr(self::RAW_KEY, 1), 'whitespace'];
        yield 'trailing newline' => [substr(self::RAW_KEY, 1) . "\n", 'whitespace'];
        yield 'inner tab' => [substr(self::RAW_KEY, 0, 16) . "\t" . substr(self::RAW_KEY, 17), 'whitespace'];
        yield 'one character short' => [substr(self::RAW_KEY, 1), '32 bytes'];
        yield 'one character long' => [self::RAW_KEY . 'x', '32 bytes'];
        yield 'base64 of 16 bytes' => ['base64' . base64_encode(str_repeat('k', 16)), '32 bytes'];
        yield 'base64 of 33 bytes' => ['base64' . base64_encode(str_repeat('k', 33)), '32 bytes'];
        yield 'base64 prefix with invalid characters' => ['base64' . str_repeat('*', 44), 'base64'];
        yield 'bare base64 prefix' => ['base64', '32 bytes'];
    }

    #[DataProvider('unusableEntries')]
    public function testAnUnusableEntryIsRefusedWithoutNamingIt(string $raw, string $reason): void
    {
        try {
            new Key($raw);
            self::fail('The entry was accepted as a key.');
        } catch (InvalidKey $refused) {
            self::assertStringContainsString($reason, $refused->getMessage());
            if (trim($raw) !== '') {
                self::assertStringNotContainsString(trim($raw), $refused->getMessage());
            }
        }
    }

    public function testTheFingerprintIsTheFirstSixteenHexOfTheSha256OfTheKeyBytes(): void
    {
        $bytes = random_bytes(32);

        $key = new Key('base64' . base64_encode($bytes));

        self::assertSame(substr(hash('sha256', $bytes), 0, 16), $key->fingerprint());
        self::assertMatchesRegularExpression('/^[0-9a-f]{16}$/', $key->fingerprint());
    }

    public function testTheFingerprintIsStableForTheSameKey(): void
    {
        self::assertSame((new Key(self::RAW_KEY))->fingerprint(), (new Key(self::RAW_KEY))->fingerprint());
        self::assertSame('3ba3f5f43b926026', (new Key(str_repeat('a', 32)))->fingerprint());
    }

    public function testTheSameBytesInBothEncodingsHaveOneFingerprintButAreDifferentEntries(): void
    {
        $plain = new Key(self::RAW_KEY);
        $encoded = new Key('base64' . base64_encode(self::RAW_KEY));

        self::assertSame($plain->fingerprint(), $encoded->fingerprint());
        self::assertFalse($plain->equals($encoded));
        self::assertTrue($plain->equals(new Key(self::RAW_KEY)));
    }

    public function testDumpingAKeyShowsOnlyItsFingerprint(): void
    {
        $bytes = random_bytes(32);
        $key = new Key('base64' . base64_encode($bytes));

        ob_start();
        var_dump($key);
        $dumped = (string) ob_get_clean();
        $printed = print_r($key, true);

        foreach ([$dumped, $printed] as $output) {
            self::assertStringContainsString($key->fingerprint(), $output);
            self::assertStringNotContainsString(base64_encode($bytes), $output);
            self::assertStringNotContainsString($bytes, $output);
        }
    }

    public function testDumpingARawKeyNeverShowsTheEntry(): void
    {
        $key = new Key(self::RAW_KEY);

        ob_start();
        var_dump($key);
        $dumped = (string) ob_get_clean();

        self::assertStringNotContainsString(self::RAW_KEY, $dumped);
        self::assertStringNotContainsString(self::RAW_KEY, print_r($key, true));
    }

    public function testAKeyIsNeverSerialised(): void
    {
        $this->expectException(\LogicException::class);

        serialize(new Key(self::RAW_KEY));
    }

    public function testAKeyIsNeverUnserialised(): void
    {
        $forged = sprintf('O:%d:"%s":0:{}', strlen(Key::class), Key::class);

        $this->expectException(\LogicException::class);

        unserialize($forged);
    }
}
