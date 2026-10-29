<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

/**
 * A ciphertext just written did not decrypt back to the plaintext it was made from; it must not be
 * stored. The message names neither the plaintext nor the key.
 */
final class RoundTripFailed extends \RuntimeException {}
