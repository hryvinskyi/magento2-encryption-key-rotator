<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * The regular expressions the database applies to stored values, written so MariaDB (PCRE) and MySQL 8
 * (ICU) match exactly the same values. They are bound as statement parameters, so no SQL escaping or
 * SQL mode changes them.
 *
 * - A whole-value ciphertext: `<key index>:<cipher version>:<base64>`, ending at the very end of the
 *   value. `\z` rather than `$`: both engines let `$` match before a final line break, and a value with a
 *   trailing line break is not in the exact form a rewrite reproduces, so it counts as embedded instead.
 * - An embedded ciphertext: the same shape, with at least 40 base64 characters, somewhere inside a
 *   larger value (a JSON document, a serialised array). A slash may appear escaped as `\/`, the way a
 *   JSON encoder writes it by default; otherwise most ciphertexts inside such a document would be missed.
 *   Such values are counted, never rewritten.
 *
 * The character classes name both letter cases, so a case-insensitive collation matches the same
 * values as a binary one.
 */
final class CiphertextPatterns
{
    public const WHOLE_VALUE = '^[0-9]{1,3}:[0-9]:[A-Za-z0-9+/]{20,}={0,2}\z';
    public const EMBEDDED = '[0-9]{1,3}:[0-9]:([A-Za-z0-9+/]|\\\\/){40,}';

    /**
     * Values that start like a ciphertext under that key index: `<index>:<version>:`.
     *
     * @throws \InvalidArgumentException when the index is not a key index
     */
    public function underKeyIndex(int $keyIndex): string
    {
        if ($keyIndex < 0 || $keyIndex > Ciphertext::MAX_KEY_INDEX) {
            throw new \InvalidArgumentException(sprintf('A key index lies between 0 and %d; %d was given.', Ciphertext::MAX_KEY_INDEX, $keyIndex));
        }

        return '^' . $keyIndex . ':[0-9]:';
    }
}
