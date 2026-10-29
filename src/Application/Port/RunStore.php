<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Keeps the runs of one Magento root, and the material each needs to undo itself, under the state
 * directory ({@see StateDirectoryProvider}): one run directory per run, readable by its owner only.
 *
 * Kept material is never replaced: keeping the same key or placeholders again is a no-op, keeping
 * different ones under the same name fails and leaves the first. Every reader returns the material as it
 * was kept, so a resumed step writes exactly what the interrupted one would have written.
 */
interface RunStore
{
    /**
     * Takes the lock of the state directory for this process.
     *
     * @throws RunLocked when another process, or another store over the same directory, holds it
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function lock(): void;

    /**
     * Releases the lock, if this store holds it.
     */
    public function unlock(): void;

    /**
     * The unfinished run, or null when every run is finished.
     *
     * @throws ConflictingRuns when more than one run is unfinished
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function active(): ?RotationRun;

    /**
     * The run started last, finished or not, or null when the store holds none.
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function latest(): ?RotationRun;

    /**
     * @throws RunNotFound when the store holds no run with that id
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function get(RunId $id): RotationRun;

    /**
     * Saves the run as it is now, replacing what was saved for it before.
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function save(RotationRun $run): void;

    /**
     * Keeps a copy of the deployment configuration as it is now, in the run's directory.
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function backupDeploymentConfig(RunId $id): void;

    /**
     * Keeps a ring entry the run needs to undo itself.
     *
     * @throws KeptMaterialConflict when the run already keeps another entry for that role and index
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function keepKey(RunId $id, KeptKeyRole $role, KeySlot $slot): void;

    /**
     * @return list<KeySlot> the entries kept for that role, in index order; empty when none are
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function keptKeys(RunId $id, KeptKeyRole $role): array;

    /**
     * Keeps the placeholders a pending retirement is about to write, so a resumed retirement writes the
     * same ones.
     *
     * @param list<KeySlot> $placeholders one retired slot per index to retire
     *
     * @throws KeptMaterialConflict when the run already keeps another set
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function keepPlaceholders(RunId $id, array $placeholders): void;

    /**
     * @return list<KeySlot> the kept placeholders, in index order; empty when none are
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function keptPlaceholders(RunId $id): array;

    /**
     * Destroys the run's directory: its kept keys first, its run record last, so a discard interrupted
     * halfway can be repeated.
     *
     * @throws UnusableStateDirectory when the state directory cannot be trusted or used
     */
    public function discard(RunId $id): void;
}
