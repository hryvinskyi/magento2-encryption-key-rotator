<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Writes the key ring and encrypted `system` values into the deployment configuration, as one
 * compare-and-swap of the whole file.
 *
 * The write happens only when the file's key ring has the expected fingerprint and every change's path
 * still holds the change's expected old ciphertext; otherwise nothing is written. It replaces the file
 * atomically (through a symbolic link, the target is replaced and the link stays), keeps everything else
 * in it, its mode and its owner, and verifies the result by reading it back.
 */
interface DeploymentConfigWriter
{
    /**
     * @param KeyRing                 $ring                    the ring `crypt/key` will hold
     * @param string                  $expectedRingFingerprint the fingerprint of the ring the file must hold now
     * @param list<SystemValueChange> $changes                 the system values to rewrite in the same write
     *
     * @throws StaleDeploymentConfig      when the file's ring or one of the paths is not as expected; nothing is written
     * @throws DeploymentConfigUnreadable when the file cannot be read, written or verified
     */
    public function write(KeyRing $ring, string $expectedRingFingerprint, array $changes): void;
}
