<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * Counts that cannot describe a scan: a negative count, or a key index out of range.
 */
final class InvalidScanSummary extends \InvalidArgumentException {}
