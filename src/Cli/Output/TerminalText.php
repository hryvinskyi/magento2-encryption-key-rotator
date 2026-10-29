<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Output;

use Symfony\Component\Console\Formatter\OutputFormatter;

/**
 * Makes text that did not come from the tool itself safe to print on a terminal: the arguments of a
 * process another local user started, a table or column name, a path, an exception message.
 *
 * Every C0 control character (U+0000 to U+001F), DEL and every C1 control character (U+0080 to U+009F)
 * is replaced by a visible `\xNN` escape, so no escape sequence, carriage return or backspace reaches
 * the terminal to move the cursor, rewrite a line already printed or change the terminal's settings.
 * Text that is not valid UTF-8 is treated byte by byte, so a lone C1 byte is escaped too. A line break
 * is escaped like any other control character: the writer adds the one that ends the line.
 */
final class TerminalText
{
    private const UTF8_CONTROLS = '/[\x00-\x1F\x7F]|\xC2[\x80-\x9F]/';
    private const BYTE_CONTROLS = '/[\x00-\x1F\x7F-\x9F]/';

    /**
     * The text with every control character replaced by its visible escape.
     */
    public function visible(string $text): string
    {
        $utf8 = preg_match('//u', $text) === 1;

        return (string) preg_replace_callback(
            $utf8 ? self::UTF8_CONTROLS : self::BYTE_CONTROLS,
            static fn(array $match): string => sprintf('\\x%02x', $utf8 && strlen($match[0]) === 2 ? ord($match[0][1]) : ord($match[0])),
            $text,
        );
    }

    /**
     * The visible text, with every `<` escaped so that the console formatter prints it as it is instead
     * of reading a style tag in it.
     */
    public function literal(string $text): string
    {
        return OutputFormatter::escape($this->visible($text));
    }
}
