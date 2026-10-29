<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Retiring the old keys would make values unreadable, or rests on a step that has not happened, and the
 * operator gave no override for it. The message names every reason.
 */
final class RetireRefused extends \DomainException {}
