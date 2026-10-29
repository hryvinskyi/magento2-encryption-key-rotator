<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * A value that is not a run id.
 */
final class InvalidRunId extends \InvalidArgumentException {}
