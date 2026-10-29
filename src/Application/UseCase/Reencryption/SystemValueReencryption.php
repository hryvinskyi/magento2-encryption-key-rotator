<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChangeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Cipher;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Moves the encrypted `system` values of the deployment configuration from source keys onto a target
 * key, in one write of the file.
 *
 * The changes are computed against the file as it is now: each carries the ciphertext its path holds,
 * and the write happens only if every path still holds it and the file's ring is the expected one, so a
 * value someone changed in between is never overwritten. The ring itself is written unchanged. A value
 * that does not decrypt under its source key stays as it is. The committed configuration is tracked and
 * deployed, so its values are never written here; a scan reports them.
 */
final class SystemValueReencryption
{
    public function __construct(
        private readonly DeploymentConfigReader $reader,
        private readonly DeploymentConfigWriter $writer,
        private readonly Cipher $cipher,
        private readonly SystemValueChangeFactory $changes,
    ) {}

    /**
     * @param array<int, Key> $sources                 key index => key, the values to move
     * @param int             $targetIndex             the index the values move to
     * @param Key             $targetKey               the key of that index
     * @param KeyRing         $ring                    the ring the file holds, written back unchanged
     * @param string          $expectedRingFingerprint the fingerprint the file's ring must have
     *
     * @return list<SystemValueChange> the changes written; empty when nothing was under a source key
     *
     * @throws InvalidValue               when the target is one of the sources
     * @throws StaleDeploymentConfig      when the file's ring or a path changed meanwhile; nothing is written
     * @throws DeploymentConfigUnreadable when the file cannot be read, written or verified
     * @throws RoundTripFailed            when a new value does not decrypt back to its plaintext; nothing is written
     */
    public function reencrypt(array $sources, int $targetIndex, Key $targetKey, KeyRing $ring, string $expectedRingFingerprint): array
    {
        if (array_key_exists($targetIndex, $sources)) {
            throw new InvalidValue(sprintf('The key index %d cannot be a source and the target of the same re-encryption.', $targetIndex));
        }
        $changes = [];
        foreach ($this->reader->systemValues() as $value) {
            $ciphertext = $value->ciphertext();
            $sourceKey = $sources[$ciphertext->keyIndex()] ?? null;
            if ($sourceKey === null || !$this->cipher->supports($ciphertext->cipherVersion())) {
                continue;
            }
            $plaintext = $this->cipher->decrypt($ciphertext, $sourceKey);
            if ($plaintext === null) {
                continue;
            }
            $changes[] = $this->changes->create(
                $value->path(),
                $ciphertext,
                $this->cipher->encrypt($plaintext, $targetIndex, $targetKey),
            );
        }
        if ($changes !== []) {
            $this->writer->write($ring, $expectedRingFingerprint, $changes);
        }

        return $changes;
    }
}
