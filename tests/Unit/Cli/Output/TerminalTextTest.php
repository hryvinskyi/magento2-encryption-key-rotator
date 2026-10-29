<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Output;

use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Text from outside the tool reaches the terminal without a control character and without a style tag.
 */
final class TerminalTextTest extends TestCase
{
    /**
     * @return iterable<string, array{string, string}>
     */
    public static function controls(): iterable
    {
        yield 'an escape sequence' => ["php bin/magento \e[2J\e[H", 'php bin/magento \x1b[2J\x1b[H'];
        yield 'a carriage return that rewrites the line' => ["cron\rOK", 'cron\x0dOK'];
        yield 'a line break' => ["one\ntwo", 'one\x0atwo'];
        yield 'a NUL byte and a backspace' => ["a\0b\x08c", 'a\x00b\x08c'];
        yield 'DEL' => ["a\x7Fb", 'a\x7fb'];
        yield 'a C1 control sequence introducer in UTF-8' => ["a\u{9B}31mb", 'a\x9b31mb'];
        yield 'a lone C1 byte in text that is not UTF-8' => ["a\x9B31m\xFFb", "a\\x9b31m\xFFb"];
    }

    #[DataProvider('controls')]
    public function testEveryControlCharacterBecomesAVisibleEscape(string $text, string $visible): void
    {
        self::assertSame($visible, (new TerminalText())->visible($text));
    }

    public function testPrintableTextIsLeftAsItIs(): void
    {
        $text = 'Ünïcödé table «sales_order» — 100 % done, a\\b';

        self::assertSame($text, (new TerminalText())->visible($text));
    }

    public function testLiteralTextIsNeverReadAsAStyleTag(): void
    {
        $formatter = new OutputFormatter(true);

        $printed = $formatter->format((new TerminalText())->literal("<error>forged</error>\e[31m"));

        self::assertSame('<error>forged</error>\x1b[31m', $printed);
    }
}
