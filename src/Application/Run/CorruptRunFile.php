<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Run;

/**
 * A saved run that cannot be read back: a missing or malformed field, a state the run could not be in.
 * The message names the run id and the field.
 */
final class CorruptRunFile extends \RuntimeException {}
