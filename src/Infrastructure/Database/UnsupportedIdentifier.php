<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * A table or column name the tool does not put into a statement: only letters, digits, `_` and `$`, at
 * most 64 characters, are quoted; anything else is refused rather than escaped.
 */
final class UnsupportedIdentifier extends \InvalidArgumentException {}
