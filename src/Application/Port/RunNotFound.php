<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The state directory holds no run with that id.
 */
final class RunNotFound extends \RuntimeException {}
