<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunNotFound;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\RunSnapshotReader;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectDateTimeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanSummaryFactory;

/**
 * A run store in memory, with the semantics of the one on disk.
 *
 * A run is kept as the JSON of its snapshot and read back through the real {@see RunSnapshotReader}, so
 * what a use case gets back is exactly what a reload from disk would give it, and a field the snapshot
 * forgets is lost here too. The lock is held per handle: {@see concurrentHandle()} opens a second handle
 * onto the same state, as a second process would. A crash hook runs right after every save and may
 * throw, so a test can stop a use case between the save of a pending state and the write it announces.
 */
final class InMemoryRunStore implements RunStore
{
    private readonly InMemoryRunStoreState $state;

    private ?\Closure $afterSave = null;

    public function __construct(
        private readonly RunSnapshotReader $reader = new RunSnapshotReader(
            new DirectRotationRunFactory(),
            new DirectRunIdFactory(),
            new DirectScanSummaryFactory(),
            new DirectDateTimeFactory(),
        ),
        ?InMemoryRunStoreState $state = null,
        private readonly ?CallLog $log = null,
    ) {
        $this->state = $state ?? new InMemoryRunStoreState();
    }

    /**
     * A second handle onto the same runs and kept material, with a lock of its own: what another process
     * working on the same state directory would see.
     */
    public function concurrentHandle(): self
    {
        return new self($this->reader, $this->state, $this->log);
    }

    public function lock(): void
    {
        if ($this->state->lockHolder !== null && $this->state->lockHolder !== $this) {
            throw new RunLocked('Another process holds the lock of the state directory.');
        }
        $this->state->lockHolder = $this;
    }

    public function unlock(): void
    {
        if ($this->state->lockHolder === $this) {
            $this->state->lockHolder = null;
        }
    }

    public function active(): ?RotationRun
    {
        $active = array_values(array_filter($this->all(), static fn(RotationRun $run): bool => $run->isActive()));
        if (count($active) > 1) {
            throw new ConflictingRuns(sprintf(
                'The state directory holds more than one unfinished run: %s.',
                implode(', ', array_map(static fn(RotationRun $run): string => $run->id()->toString(), $active)),
            ));
        }

        return $active[0] ?? null;
    }

    public function latest(): ?RotationRun
    {
        $latest = null;
        foreach ($this->all() as $run) {
            if ($latest === null || $run->startedAt() >= $latest->startedAt()) {
                $latest = $run;
            }
        }

        return $latest;
    }

    public function get(RunId $id): RotationRun
    {
        $json = $this->state->runs[$id->toString()] ?? null;
        if ($json === null) {
            throw new RunNotFound(sprintf('The state directory holds no run %s.', $id->toString()));
        }

        return $this->reader->read($id->toString(), json_decode($json, true, 512, JSON_THROW_ON_ERROR));
    }

    public function save(RotationRun $run): void
    {
        $this->state->runs[$run->id()->toString()] = json_encode($run->snapshot(), JSON_THROW_ON_ERROR);
        $this->log?->record('store.save ' . $run->state()->value);

        if ($this->afterSave !== null) {
            ($this->afterSave)($run);
        }
    }

    public function backupDeploymentConfig(RunId $id): void
    {
        $this->state->backups[$id->toString()] = ($this->state->backups[$id->toString()] ?? 0) + 1;
    }

    public function keepKey(RunId $id, KeptKeyRole $role, KeySlot $slot): void
    {
        $kept = $this->state->keys[$id->toString()][$role->value][$slot->index()] ?? null;
        if ($kept !== null && !hash_equals($kept, $slot->raw())) {
            throw new KeptMaterialConflict(sprintf(
                'Run %s already keeps another %s key for slot %d.',
                $id->toString(),
                $role->value,
                $slot->index(),
            ));
        }
        $this->state->keys[$id->toString()][$role->value][$slot->index()] = $slot->raw();
    }

    public function keptKeys(RunId $id, KeptKeyRole $role): array
    {
        return $this->slots($this->state->keys[$id->toString()][$role->value] ?? []);
    }

    public function keepPlaceholders(RunId $id, array $placeholders): void
    {
        $given = [];
        foreach ($placeholders as $slot) {
            $given[$slot->index()] = $slot->raw();
        }
        ksort($given);
        $kept = $this->state->placeholders[$id->toString()] ?? null;
        if ($kept !== null && $kept !== $given) {
            throw new KeptMaterialConflict(sprintf('Run %s already keeps another set of placeholders.', $id->toString()));
        }
        $this->state->placeholders[$id->toString()] = $given;
    }

    public function keptPlaceholders(RunId $id): array
    {
        return $this->slots($this->state->placeholders[$id->toString()] ?? []);
    }

    public function discard(RunId $id): void
    {
        $this->log?->record('store.discard ' . $id->toString());
        unset(
            $this->state->keys[$id->toString()],
            $this->state->placeholders[$id->toString()],
            $this->state->backups[$id->toString()],
            $this->state->runs[$id->toString()],
        );
    }

    /**
     * Runs after every save, with the saved run; it may throw to play a crash right after the run record
     * was written. Null removes the hook.
     *
     * @param (\Closure(RotationRun): void)|null $hook
     */
    public function afterSave(?\Closure $hook): void
    {
        $this->afterSave = $hook;
    }

    /**
     * How many times the deployment configuration was backed up for the run.
     */
    public function backupCount(RunId $id): int
    {
        return $this->state->backups[$id->toString()] ?? 0;
    }

    /**
     * Whether the store still holds anything of the run: its record, kept keys, placeholders or backup.
     */
    public function holdsAnythingOf(RunId $id): bool
    {
        $key = $id->toString();

        return isset($this->state->runs[$key])
            || isset($this->state->keys[$key])
            || isset($this->state->placeholders[$key])
            || isset($this->state->backups[$key]);
    }

    /**
     * @return list<RotationRun> every run, in the order they were first saved
     */
    private function all(): array
    {
        $runs = [];
        foreach (array_keys($this->state->runs) as $id) {
            $runs[] = $this->reader->read($id, json_decode($this->state->runs[$id], true, 512, JSON_THROW_ON_ERROR));
        }

        return $runs;
    }

    /**
     * @param array<int, string> $entries index => entry
     *
     * @return list<KeySlot>
     */
    private function slots(array $entries): array
    {
        ksort($entries);
        $slots = [];
        foreach ($entries as $index => $raw) {
            $slots[] = new KeySlot($index, $raw);
        }

        return $slots;
    }
}
