<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * A deployment configuration write found the file other than expected: its key ring has another
 * fingerprint, or a system value no longer holds the ciphertext the change expects. Nothing was written.
 * The message names the fingerprints or the path, never a value.
 */
final class StaleDeploymentConfig extends \RuntimeException {}
