<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

/**
 * A ring entry that is not a usable encryption key. The message says why, never what the entry holds.
 */
final class InvalidKey extends \InvalidArgumentException {}
