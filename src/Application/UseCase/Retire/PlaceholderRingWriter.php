<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\CiphertextVerifier;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RetireRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Psr\Clock\ClockInterface;

/**
 * Replaces the keys of a run's moved indices by placeholders in the key ring, so that a crash at any
 * point can be resumed and always writes the same placeholders.
 *
 * The write is announced before it happens:
 * 1. the placeholders are chosen: the ones the run already keeps, or new ones;
 * 2. the run records `retire_pending` with the fingerprint of the ring with the placeholders (the run
 *    refuses here when values would become unreadable or a required step is missing);
 * 3. every key being replaced is kept in the run store (role `retired`), then the placeholders, then the
 *    run is saved;
 * 4. the deployment configuration is written by compare-and-swap on the ring the run recorded.
 *
 * Resuming a `retire_pending` run reads the file's ring every time:
 * - it is the ring the run recorded before the retirement: the write did not happen, and is made again
 *   with the kept placeholders, never new ones, once the committed configuration (app/etc/config.php,
 *   which a deploy may have replaced since the retirement was announced) holds no value that still
 *   decrypts under a moved index, the check a new retirement makes before it announces the write;
 * - it is the announced ring: the write happened before the crash;
 * - it is anything else: another writer changed the file; nothing is written and both fingerprints are
 *   named.
 */
final class PlaceholderRingWriter
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $reader,
        private readonly DeploymentConfigWriter $writer,
        private readonly KeyGenerator $generator,
        private readonly KeySlotFactory $slots,
        private readonly KeyRingFactory $rings,
        private readonly CiphertextVerifier $verifier,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * Keeps what the retirement replaces and records `retire_pending`; nothing is written yet.
     *
     * @param RotationRun       $run       a `reencrypted` run whose last scan is recorded
     * @param KeyRing           $ring      the ring the deployment configuration holds, the one the run recorded
     * @param list<RunOverride> $overrides the checks the operator waived for the retirement
     *
     * @return KeyRing the ring the retirement is about to write
     *
     * @throws RetireRefused        when values would become unreadable or a required step is missing; nothing is kept
     * @throws KeyRingChangeRefused when a moved index cannot be retired in that ring; nothing is kept
     * @throws KeptMaterialConflict when the run keeps placeholders for other indices, or another key for one of them
     */
    public function announce(RotationRun $run, KeyRing $ring, array $overrides): KeyRing
    {
        $indices = $run->movedIndices();
        $placeholders = $this->placeholders($run, $indices);
        $intended = $ring->withRetired(
            $indices,
            array_map(static fn(KeySlot $slot): string => $slot->raw(), $placeholders),
            $this->slots,
            $this->rings,
        );
        $run->retirePending($intended->fingerprint(), $overrides, $this->clock->now());

        foreach ($indices as $index) {
            $slot = $ring->slot($index) ?? throw new KeyRingChangeRefused(sprintf('The key ring has no slot %d to retire.', $index));
            $this->runs->keepKey($run->id(), KeptKeyRole::Retired, $slot);
        }
        $this->runs->keepPlaceholders($run->id(), $placeholders);
        $this->runs->save($run);

        return $intended;
    }

    /**
     * Writes the announced ring over the ring the run recorded.
     *
     * @return Refusal|null why nothing was written, or null when the ring with the placeholders is in place
     */
    public function write(RotationRun $run, KeyRing $intended): ?Refusal
    {
        $this->progress->step(sprintf(
            'Retiring the keys of indices %s: key ring %s becomes %s',
            implode(', ', $run->movedIndices()),
            $run->ringFingerprint(),
            $intended->fingerprint(),
        ));
        try {
            $this->writer->write($intended, $run->ringFingerprint(), []);
        } catch (StaleDeploymentConfig $stale) {
            return $this->refusals->create(RefusalReason::RingChanged, $stale->getMessage());
        }

        return null;
    }

    /**
     * Finishes the announced write of a `retire_pending` run, with the placeholders it kept.
     *
     * @return Refusal|null why nothing was written, or null when the ring with the placeholders is in place
     */
    public function resume(RotationRun $run): ?Refusal
    {
        $ring = $this->reader->keyRing();
        $found = $ring->fingerprint();
        $intended = $run->intendedRingFingerprint();
        if ($found === $intended) {
            $this->progress->step(sprintf('The key ring %s with the placeholders is already written', $found));

            return null;
        }
        if ($found !== $run->ringFingerprint()) {
            return $this->refusals->create(RefusalReason::RingChanged, sprintf(
                'The deployment configuration holds the key ring %s, but run %s expects %s (before retiring) or %s (after it): another writer changed it. Nothing was written.',
                $found,
                $run->id()->toString(),
                $run->ringFingerprint(),
                (string) $intended,
            ));
        }

        $committed = $this->committedValuesOnMovedIndices($run);
        if ($committed !== null) {
            return $committed;
        }

        $indices = $run->movedIndices();
        $kept = $this->runs->keptPlaceholders($run->id());
        if (array_map(static fn(KeySlot $slot): int => $slot->index(), $kept) !== $indices) {
            return $this->refusals->create(RefusalReason::KeptMaterialMissing, sprintf(
                'Run %s does not keep the placeholders of indices %s it announced; nothing was written. Roll the run back.',
                $run->id()->toString(),
                implode(', ', $indices),
            ));
        }
        $rebuilt = $ring->withRetired(
            $indices,
            array_map(static fn(KeySlot $slot): string => $slot->raw(), $kept),
            $this->slots,
            $this->rings,
        );
        if ($rebuilt->fingerprint() !== $intended) {
            return $this->refusals->create(RefusalReason::KeptMaterialMissing, sprintf(
                'The kept placeholders of run %s make the key ring %s, but the run announced %s; nothing was written. Roll the run back.',
                $run->id()->toString(),
                $rebuilt->fingerprint(),
                (string) $intended,
            ));
        }

        return $this->write($run, $rebuilt);
    }

    /**
     * Refuses the ring write while the committed configuration holds values that still decrypt under a
     * moved index: the tool never writes that file, so once their keys are placeholders nothing reads
     * them.
     */
    private function committedValuesOnMovedIndices(RotationRun $run): ?Refusal
    {
        $ring = $this->reader->keyRing();
        $moved = $run->movedIndices();
        $paths = array_map(
            static fn(SystemValue $value): string => $value->pathString(),
            array_values(array_filter(
                $this->reader->committedSystemValues(),
                fn(SystemValue $value): bool => in_array($value->ciphertext()->keyIndex(), $moved, true)
                    && $this->verifier->verdict($value->ciphertext(), $ring) === ValueVerdict::Verified,
            )),
        );
        if ($paths === []) {
            return null;
        }

        return $this->refusals->create(RefusalReason::RetireBlocked, sprintf(
            'Run %s cannot write its placeholders yet: app/etc/config.php holds values under the old key indices %s: %s. Deploy that file with those values encrypted under the new key, then run retire again. Nothing was written.',
            $run->id()->toString(),
            implode(', ', $moved),
            implode(', ', $paths),
        ));
    }

    /**
     * @param list<int> $indices
     *
     * @return list<KeySlot> one placeholder per index: the kept ones, or new ones when the run keeps none
     *
     * @throws KeptMaterialConflict when the run keeps placeholders for other indices
     */
    private function placeholders(RotationRun $run, array $indices): array
    {
        $kept = $this->runs->keptPlaceholders($run->id());
        if ($kept !== []) {
            if (array_map(static fn(KeySlot $slot): int => $slot->index(), $kept) !== $indices) {
                throw new KeptMaterialConflict(sprintf(
                    'Run %s keeps placeholders for other indices than %s.',
                    $run->id()->toString(),
                    implode(', ', $indices),
                ));
            }

            return $kept;
        }

        return array_map(fn(int $index): KeySlot => $this->slots->create($index, $this->generator->placeholder()), $indices);
    }
}
