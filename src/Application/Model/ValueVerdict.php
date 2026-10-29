<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What checking one stored value found: it decrypts under the key of its index, or why it does not.
 *
 * A value that does not decrypt is never modified; it is reported with its reason:
 * - the slot of its index is retired (its key was replaced by a placeholder);
 * - the ring has no slot at its index;
 * - its cipher version is one the tool does not read;
 * - it does not authenticate under the key of its index.
 * A value that has the shape of a ciphertext but is not one in the exact form the store writes (an old
 * four-part value, a non-canonical payload) is unparsable.
 */
enum ValueVerdict: string
{
    case Verified = 'verified';
    case RetiredKey = 'retired_key';
    case UnknownKey = 'unknown_key';
    case UnsupportedCipher = 'unsupported_cipher';
    case AuthenticationFailed = 'authentication_failed';
    case Unparsable = 'unparsable';

    public function isVerified(): bool
    {
        return $this === self::Verified;
    }
}
