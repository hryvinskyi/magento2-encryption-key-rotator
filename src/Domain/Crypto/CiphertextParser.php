<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

/**
 * Recognises a stored value as a ciphertext, strictly: `<key index>:<cipher version>:<payload>` and
 * nothing around it, with the parts in the exact form the store writes them.
 *
 * Anything else is not a ciphertext and yields null, never an exception: the parser reads foreign data.
 * That includes the four-part `<key>:<version>:<iv>:<data>` form of the oldest ciphers, which the tool
 * does not handle, a value with surrounding whitespace, a key index with a leading zero, and a payload
 * that is not canonical base64. Rejecting those keeps {@see Ciphertext::toString()} byte-identical to
 * every value the parser accepts.
 */
final class CiphertextParser
{
    private const SHAPE = '~^(0|[1-9][0-9]{0,2}):([0-9]):([A-Za-z0-9+/]+={0,2})$~D';

    public function __construct(
        private readonly CiphertextFactory $ciphertexts,
    ) {}

    public function parse(string $value): ?Ciphertext
    {
        if (preg_match(self::SHAPE, $value, $parts) !== 1) {
            return null;
        }

        try {
            return $this->ciphertexts->create((int) $parts[1], (int) $parts[2], $parts[3]);
        } catch (InvalidCiphertext) {
            return null;
        }
    }
}
