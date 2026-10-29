<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Crypto;

/**
 * Parts that do not form a stored ciphertext: a key index or cipher version out of range, or a payload
 * that is not canonical base64.
 */
final class InvalidCiphertext extends \InvalidArgumentException {}
