<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A value the ports cannot exchange: an empty name, a malformed address or pattern, a negative count.
 * The message says what is wrong, never a secret the value held.
 */
final class InvalidValue extends \InvalidArgumentException {}
