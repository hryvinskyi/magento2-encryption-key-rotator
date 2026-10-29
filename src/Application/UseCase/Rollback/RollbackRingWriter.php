<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Psr\Clock\ClockInterface;

/**
 * The key ring writes of a rollback, each read from the file as it is now so a repeated rollback finds
 * what an interrupted one already did:
 * - {@see reconcile()}: a write the run announced and that is found in place is recorded; a ring the run
 *   never recorded is refused;
 * - {@see restoreRetired()}: every slot the run retired that holds a placeholder gets its kept key back;
 * - {@see removeNewSlot()}: the slot the run appended is removed only when it is the run's new index and
 *   holds exactly the kept new key; a ring that already is the ring before the run is left as it is, any
 *   other ring is refused naming both fingerprints. A slot is never removed by its position alone.
 *
 * Every write is announced first: the run records the fingerprint of the ring about to be written and is
 * saved, then the file is written by compare-and-swap on the ring found, then the write is recorded.
 */
final class RollbackRingWriter
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $reader,
        private readonly DeploymentConfigWriter $writer,
        private readonly KeySlotFactory $slots,
        private readonly KeyRingFactory $rings,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * Matches the file's ring against what the run knows: the ring it last recorded, the ring before the
     * run, or a ring it announced (recorded as written now).
     *
     * @param RotationRun $run a run that is rolling back
     *
     * @return Refusal|null why the rollback cannot go on, or null when the ring is one the run knows
     */
    public function reconcile(RotationRun $run): ?Refusal
    {
        $found = $this->reader->keyRing()->fingerprint();
        $intended = $run->intendedRingFingerprint();
        if ($intended !== null && $found === $intended && $found !== $run->ringFingerprint()) {
            $this->progress->step(sprintf('The announced key ring %s is already written', $found));
            $run->rollbackRingWritten($found, $this->clock->now());
            $this->runs->save($run);

            return null;
        }
        if ($found === $run->ringFingerprint() || $found === $run->ringFingerprintBefore()) {
            return null;
        }

        return $this->refusals->create(RefusalReason::RingChanged, sprintf(
            'The deployment configuration holds the key ring %s, but run %s recorded %s, and the ring before the run was %s: another writer changed it. Nothing was written.',
            $found,
            $run->id()->toString(),
            $run->ringFingerprint(),
            $run->ringFingerprintBefore(),
        ));
    }

    /**
     * Puts the kept key back into every slot the run retired that holds a placeholder.
     *
     * @return Refusal|null why nothing was written, or null when no retired slot of the run holds a placeholder any more
     */
    public function restoreRetired(RotationRun $run): ?Refusal
    {
        $ring = $this->reader->keyRing();
        $restored = $ring;
        $indices = [];
        try {
            foreach ($this->runs->keptKeys($run->id(), KeptKeyRole::Retired) as $kept) {
                if ($restored->slot($kept->index())?->isRetired() === true) {
                    $restored = $restored->withRestored($kept->index(), $kept->raw(), $this->slots, $this->rings);
                    $indices[] = $kept->index();
                }
            }
        } catch (KeyRingChangeRefused|InvalidKey $refused) {
            return $this->refusals->create(RefusalReason::KeptMaterialMissing, sprintf(
                'Run %s cannot put its retired keys back: %s Nothing was written.',
                $run->id()->toString(),
                $refused->getMessage(),
            ));
        }
        if ($indices === []) {
            return null;
        }

        $this->progress->step(sprintf(
            'Putting the retired keys of indices %s back: key ring %s becomes %s',
            implode(', ', $indices),
            $ring->fingerprint(),
            $restored->fingerprint(),
        ));

        return $this->write($run, $restored, $ring->fingerprint());
    }

    /**
     * Removes the slot the run appended, identified by its index and the kept new key.
     *
     * @param Key|null $newKey the kept new key, or null when the run never appended one
     *
     * @return Refusal|null why nothing was written, or null when the file holds the ring before the run
     */
    public function removeNewSlot(RotationRun $run, ?Key $newKey): ?Refusal
    {
        $ring = $this->reader->keyRing();
        $found = $ring->fingerprint();
        $before = $run->ringFingerprintBefore();
        if ($found === $before) {
            return null;
        }
        $newIndex = $run->newIndex();
        if ($newIndex === null || $newKey === null) {
            return $this->otherRing($run, $found, 'the run appended no key it could remove');
        }
        try {
            $target = $ring->withoutSlot($newIndex, $newKey, $this->rings);
        } catch (KeyRingChangeRefused $refused) {
            return $this->otherRing($run, $found, $refused->getMessage());
        }
        if ($target->fingerprint() !== $before) {
            return $this->otherRing($run, $found, sprintf('without slot %d it would be %s', $newIndex, $target->fingerprint()));
        }

        $this->progress->step(sprintf(
            'Removing the new key %s from slot %d: key ring %s becomes %s',
            $newKey->fingerprint(),
            $newIndex,
            $found,
            $target->fingerprint(),
        ));

        return $this->write($run, $target, $found);
    }

    private function write(RotationRun $run, KeyRing $target, string $expected): ?Refusal
    {
        $run->rollbackRingPending($target->fingerprint(), $this->clock->now());
        $this->runs->save($run);
        try {
            $this->writer->write($target, $expected, []);
        } catch (StaleDeploymentConfig $stale) {
            return $this->refusals->create(RefusalReason::RingChanged, $stale->getMessage());
        }
        $run->rollbackRingWritten($target->fingerprint(), $this->clock->now());
        $this->runs->save($run);

        return null;
    }

    private function otherRing(RotationRun $run, string $found, string $why): Refusal
    {
        return $this->refusals->create(RefusalReason::RingChanged, sprintf(
            'The deployment configuration holds the key ring %s, not the ring %s run %s started from, and the new key cannot be removed from it (%s). Nothing was written.',
            $found,
            $run->ringFingerprintBefore(),
            $run->id()->toString(),
            rtrim($why, '.'),
        ));
    }
}
