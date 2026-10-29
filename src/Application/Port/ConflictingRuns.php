<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The state directory holds more than one unfinished run, which a single Magento root never may. The
 * message names every id.
 */
final class ConflictingRuns extends \RuntimeException {}
