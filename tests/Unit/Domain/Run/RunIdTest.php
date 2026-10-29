<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidRunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class RunIdTest extends TestCase
{
    public function testARunIdIs32LowercaseHexCharacters(): void
    {
        $id = new RunId('0123456789abcdef0123456789abcdef');

        self::assertSame('0123456789abcdef0123456789abcdef', $id->toString());
        self::assertTrue($id->equals(new RunId('0123456789abcdef0123456789abcdef')));
        self::assertFalse($id->equals(new RunId('ffffffffffffffffffffffffffffffff')));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function notRunIds(): iterable
    {
        yield 'empty' => [''];
        yield 'too short' => ['0123456789abcdef'];
        yield 'too long' => ['0123456789abcdef0123456789abcdef0'];
        yield 'uppercase' => ['0123456789ABCDEF0123456789ABCDEF'];
        yield 'a trailing newline' => ["0123456789abcdef0123456789abcdef\n"];
        yield 'a path' => ['../../../../../../../../etc/passw'];
    }

    #[DataProvider('notRunIds')]
    public function testAnythingElseIsRefused(string $value): void
    {
        $this->expectException(InvalidRunId::class);

        new RunId($value);
    }
}
