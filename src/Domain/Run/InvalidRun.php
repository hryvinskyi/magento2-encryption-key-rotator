<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Fields that do not describe a rotation run: a malformed fingerprint, an index out of place, or a state
 * without the facts that state requires.
 */
final class InvalidRun extends \InvalidArgumentException {}
