<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

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
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Psr\Clock\ClockInterface;

/**
 * Starts a rotation run and appends its new key to the key ring, so that a crash at any point can be
 * resumed without ever appending a second key.
 *
 * The write is announced before it happens: the key is kept in the run store first, then the run records
 * `key_pending` with the fingerprint of the ring it is about to write, then the deployment configuration
 * is written by compare-and-swap on the ring the run started from, then the run records `key_added`.
 * Resuming reads the file's ring every time:
 * - it is the ring the run started from: the write did not happen, and is made again with the kept key;
 * - it is the announced ring: the write happened before the crash, and only `key_added` is recorded;
 * - it is anything else: another writer changed the file; nothing is written and both fingerprints are
 *   named.
 */
final class NewKeyAppender
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $reader,
        private readonly DeploymentConfigWriter $writer,
        private readonly KeyGenerator $generator,
        private readonly KeyFactory $keys,
        private readonly KeySlotFactory $slots,
        private readonly KeyRingFactory $rings,
        private readonly RotationRunFactory $runFactory,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * The key a new run would append: the operator's entry, or a newly drawn key, checked to fit the ring.
     *
     * @throws InvalidKey           when the entry is not a usable key
     * @throws KeyRingChangeRefused when the ring already holds the key or cannot take another one
     */
    public function candidate(KeyRing $ring, #[\SensitiveParameter] ?string $rawKey): Key
    {
        $key = $rawKey === null ? $this->generator->generate() : $this->keys->create($rawKey);
        $ring->appended($key, $this->slots, $this->rings);

        return $key;
    }

    /**
     * Starts a run on the ring as it is, keeps a copy of the deployment configuration in the run
     * directory and saves the run.
     *
     * @param RunId             $id     the run's id, under which it claimed the store
     * @param list<RunOverride> $waived the checks the operator waived before the run started
     */
    public function start(RunId $id, KeyRing $ring, array $waived): RotationRun
    {
        $now = $this->clock->now();
        $run = $this->runFactory->start($id, $ring->fingerprint(), $ring->usableOldIndices(), $ring->activeIndex(), $now);
        foreach ($waived as $override) {
            $run->overridden($override, $now);
        }
        $this->progress->step(sprintf('Starting run %s', $run->id()->toString()));
        $this->runs->backupDeploymentConfig($run->id());
        $this->runs->save($run);

        return $run;
    }

    /**
     * Appends the run's key to the ring, or records that it was appended before an interruption.
     *
     * @param RotationRun $run       a run that is `started` or `key_pending`
     * @param Key|null    $candidate the key to append when the run keeps none yet; a new one is drawn when null
     *
     * @return Refusal|null why nothing was written, or null when the run is `key_added`
     */
    public function append(RotationRun $run, ?Key $candidate): ?Refusal
    {
        $ring = $this->reader->keyRing();
        $found = $ring->fingerprint();
        if ($found === $run->intendedRingFingerprint()) {
            $this->progress->step(sprintf('The key ring %s with the new key is already written', $found));
            $run->keyAdded($found, $this->clock->now());
            $this->runs->save($run);

            return null;
        }
        if ($found !== $run->ringFingerprint()) {
            return $this->ringChanged($run, $found);
        }

        $newIndex = $run->activeIndexBefore() + 1;
        $kept = $this->keptKey($run, $newIndex);
        if ($kept !== null && $candidate !== null && !$kept->equals($candidate)) {
            $this->progress->warn(sprintf('Run %s already keeps its new key %s; the key given is not used.', $run->id()->toString(), $kept->fingerprint()));
        }
        $key = $kept ?? $candidate ?? $this->generator->generate();
        try {
            $intended = $ring->appended($key, $this->slots, $this->rings);
        } catch (KeyRingChangeRefused $refused) {
            return $this->refusals->create(RefusalReason::KeyRejected, $refused->getMessage());
        }

        $this->runs->keepKey($run->id(), KeptKeyRole::Added, $this->slots->create($newIndex, $key->raw()));
        $run->keyPending($newIndex, $intended->fingerprint(), $this->clock->now());
        $this->runs->save($run);

        $this->progress->step(sprintf('Appending the key %s as slot %d: key ring %s becomes %s', $key->fingerprint(), $newIndex, $found, $intended->fingerprint()));
        try {
            $this->writer->write($intended, $run->ringFingerprint(), []);
        } catch (StaleDeploymentConfig $stale) {
            return $this->refusals->create(RefusalReason::RingChanged, $stale->getMessage());
        }
        $run->keyAdded($intended->fingerprint(), $this->clock->now());
        $this->runs->save($run);

        return null;
    }

    private function keptKey(RotationRun $run, int $index): ?Key
    {
        foreach ($this->runs->keptKeys($run->id(), KeptKeyRole::Added) as $slot) {
            if ($slot->index() === $index) {
                return $slot->key($this->keys);
            }
        }

        return null;
    }

    private function ringChanged(RotationRun $run, string $found): Refusal
    {
        $intended = $run->intendedRingFingerprint();

        return $this->refusals->create(RefusalReason::RingChanged, sprintf(
            'The deployment configuration holds the key ring %s, but run %s expects %s%s: another writer changed it. Nothing was written.',
            $found,
            $run->id()->toString(),
            $run->ringFingerprint(),
            $intended === null ? '' : sprintf(' (before its key write) or %s (after it)', $intended),
        ));
    }
}
