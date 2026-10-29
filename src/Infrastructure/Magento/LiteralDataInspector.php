<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

/**
 * Tells whether PHP source returns nothing but literal data: arrays (short or long syntax) of quoted
 * strings, integers, floats, `true`, `false` and `null`, with comments and whitespace around them.
 *
 * Such a file evaluates to the same array wherever and whenever it runs, so writing the evaluated array
 * back loses nothing but its comments. Anything else (a function call such as `getenv()`, a variable, a
 * constant, `__DIR__`, an include, a string with interpolation, a heredoc) makes the answer false:
 * rewriting that file would replace an expression with the value it had in this process, baking a value
 * of the environment into the file.
 */
final class LiteralDataInspector
{
    private const TOKENS = [
        T_OPEN_TAG,
        T_CLOSE_TAG,
        T_RETURN,
        T_ARRAY,
        T_CONSTANT_ENCAPSED_STRING,
        T_LNUMBER,
        T_DNUMBER,
        T_DOUBLE_ARROW,
        T_WHITESPACE,
        T_COMMENT,
        T_DOC_COMMENT,
    ];

    /**
     * Brackets of both array syntaxes, separators, and the signs of a negative or positive number.
     */
    private const CHARACTERS = ['[', ']', '(', ')', ',', ';', '-', '+'];

    /**
     * The only bare words of literal data; PHP reads them case-insensitively.
     */
    private const WORDS = ['true', 'false', 'null'];

    public function holdsOnlyLiteralData(string $source): bool
    {
        foreach (token_get_all($source) as $token) {
            if (is_string($token)) {
                if (!in_array($token, self::CHARACTERS, true)) {
                    return false;
                }

                continue;
            }
            [$id, $text] = $token;
            if ($id === T_STRING) {
                if (!in_array(strtolower($text), self::WORDS, true)) {
                    return false;
                }

                continue;
            }
            if (!in_array($id, self::TOKENS, true)) {
                return false;
            }
        }

        return true;
    }
}
