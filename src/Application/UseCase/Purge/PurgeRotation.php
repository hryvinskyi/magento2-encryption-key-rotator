<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunNotFound;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StoreClaim;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\VerifiedValuesOnIndices;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Psr\Clock\ClockInterface;

/**
 * Destroys what a finished run kept to undo itself: its journal of old values and its run directory, the
 * kept keys with it. After it the run can no longer be rolled back, and the state directory no longer
 * knows it: "purged" means gone.
 *
 * Only a `retired` or a `rolled_back` run is purged. In order:
 * 1. the indices the purge makes unreadable for good are rescanned with the kept keys standing in for
 *    their slots: a retired run's moved indices, a rolled-back run's new index. A value there that still
 *    decrypts with a kept key refuses the purge, and so does a whole ciphertext there in a column without
 *    a row key (it cannot be verified, and nothing reads it once the keys are gone), and so do embedded
 *    values and columns the scan could not judge in full, since they may hold such values; the operator
 *    may accept the loss, which the result states with the counts, each kind on its own;
 * 2. the run's journal entries are deleted;
 * 3. the store's claim is given up ({@see StoreClaim}), so the next rotation, from any state directory,
 *    may start;
 * 4. the run directory is destroyed, kept keys first and the run record last;
 * 5. the run records `purged`, in memory only: its record is gone.
 *
 * A purge interrupted after its first deletion is finished by running it again, and a purge of a run that
 * is already gone does nothing. Every refusal is a result, never an exception; the call holds the run
 * store's lock throughout.
 */
final class PurgeRotation
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly ScanEncryptedData $scanner,
        private readonly VerifiedValuesOnIndices $verified,
        private readonly JournalPurger $journal,
        private readonly StoreClaim $claim,
        private readonly KeyFactory $keys,
        private readonly ScanScopeFactory $scopes,
        private readonly PurgeResultFactory $results,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @throws RunLocked       when another process holds the run store's lock
     * @throws ConflictingRuns when the run store holds more than one unfinished run
     */
    public function purge(PurgeRequest $request): PurgeResult
    {
        $this->runs->lock();
        try {
            $run = $this->find($request);
            if ($run === null) {
                return $this->results->stopped(
                    status: PurgeStatus::NothingToPurge,
                    runId: $request->runId(),
                    state: null,
                    refusals: [],
                    scan: null,
                    purgedIndices: [],
                    stillReadable: 0,
                    embedded: 0,
                    incompleteColumns: 0,
                    withoutRowKey: 0,
                );
            }
            $refusal = $this->stateRefusal($run);
            if ($refusal !== null) {
                return $this->refused($run, $refusal, null, [], 0);
            }

            return $this->purgeRun($run, $request);
        } finally {
            $this->runs->unlock();
        }
    }

    private function purgeRun(RotationRun $run, PurgeRequest $request): PurgeResult
    {
        $indices = $this->purgedIndices($run);
        $this->progress->step(sprintf('Scanning key indices %s with the kept keys', $indices === [] ? 'none' : implode(', ', $indices)));
        $scan = $this->scanner->scan($this->scopes->create([]), $this->keptKeys($run), ScanEncryptedData::DEFAULT_BATCH_SIZE);
        $summary = $scan->summary();
        $stillReadable = $summary->verifiedOnAny($indices);
        $withoutRowKey = $summary->withoutRowKeyOnAny($indices);
        $atRisk = $stillReadable > 0 || $withoutRowKey > 0 || $summary->hasUnjudgedValues();
        if ($atRisk && !$request->acceptsLoss()) {
            return $this->refused($run, $this->refusals->create(RefusalReason::ValuesStillReadable, $this->lossMessage($run, $scan, $indices, $stillReadable)), $scan, $indices, $stillReadable);
        }
        if ($atRisk) {
            $this->progress->warn($this->lossMessage($run, $scan, $indices, $stillReadable) . ' The loss was accepted.');
        }

        $this->progress->step(sprintf('Deleting the journal of run %s', $run->id()->toString()));
        $deleted = $this->journal->purge($run->id());
        $this->claim->release($run->id());
        $this->progress->step(sprintf('Destroying the run directory of run %s and the keys it kept', $run->id()->toString()));
        $this->runs->discard($run->id());
        $run->purged($atRisk, $this->clock->now());

        return $this->results->purged(
            status: PurgeStatus::Purged,
            runId: $run->id(),
            state: $run->state(),
            scan: $scan,
            purgedIndices: $indices,
            stillReadable: $stillReadable,
            embedded: $summary->embedded(),
            incompleteColumns: $summary->incompleteColumns(),
            withoutRowKey: $withoutRowKey,
            acceptedLoss: $atRisk,
            journalEntriesDeleted: $deleted,
            runDirectoryRemoved: true,
        );
    }

    private function find(PurgeRequest $request): ?RotationRun
    {
        $id = $request->runId();
        if ($id !== null) {
            try {
                return $this->runs->get($id);
            } catch (RunNotFound) {
                return null;
            }
        }

        return $this->runs->active() ?? $this->runs->latest();
    }

    private function stateRefusal(RotationRun $run): ?Refusal
    {
        return match ($run->state()) {
            RunState::Retired, RunState::RolledBack => null,
            RunState::RollingBack => $this->refusals->create(
                RefusalReason::RollbackInProgress,
                sprintf('Run %s is rolling back; only the rollback may continue it. Run rollback again, then purge.', $run->id()->toString()),
            ),
            default => $this->refusals->create(RefusalReason::StateDoesNotAllow, sprintf(
                'Run %s is "%s"; only a run that is "%s" or "%s" can be purged, since purging destroys what undoing it needs.',
                $run->id()->toString(),
                $run->state()->value,
                RunState::Retired->value,
                RunState::RolledBack->value,
            )),
        };
    }

    /**
     * @return list<int> the indices only the run's kept keys still decrypt: a retired run's moved indices,
     *                   a rolled-back run's new index
     */
    private function purgedIndices(RotationRun $run): array
    {
        if ($run->state() === RunState::Retired) {
            return $run->movedIndices();
        }
        $newIndex = $run->newIndex();

        return $newIndex === null ? [] : [$newIndex];
    }

    /**
     * @return array<int, Key> index => every key the run kept for it
     */
    private function keptKeys(RotationRun $run): array
    {
        $keys = [];
        foreach ([KeptKeyRole::Retired, KeptKeyRole::Added] as $role) {
            foreach ($this->runs->keptKeys($run->id(), $role) as $slot) {
                $key = $slot->key($this->keys);
                if ($key !== null) {
                    $keys[$slot->index()] = $key;
                }
            }
        }

        return $keys;
    }

    /**
     * @param list<int> $indices
     */
    private function lossMessage(RotationRun $run, ScanReport $scan, array $indices, int $stillReadable): string
    {
        $parts = [];
        if ($stillReadable > 0) {
            $parts[] = sprintf(
                '%d values on key indices %s still decrypt only with the keys run %s kept (%s)',
                $stillReadable,
                implode(', ', $indices),
                $run->id()->toString(),
                $this->verified->describe($scan, $indices),
            );
        }
        $withoutRowKey = $this->verified->withoutRowKey($scan, $indices);
        if ($withoutRowKey !== []) {
            $parts[] = sprintf(
                '%d values on key indices %s sit in columns whose table has no row key (%s): the scan cannot verify them, and they become unreadable with the keys',
                array_sum($withoutRowKey),
                implode(', ', $indices),
                implode(', ', array_keys($withoutRowKey)),
            );
        }
        $summary = $scan->summary();
        if ($summary->hasUnjudgedValues()) {
            $parts[] = sprintf(
                '%d embedded values and %d columns the scan could not judge in full may hold such values',
                $summary->embedded(),
                $summary->incompleteColumns(),
            );
        }

        return sprintf(
            '%s. Purging would make them unreadable for good: move them onto a key of the ring first, or pass --accept-loss.',
            ucfirst(implode('; ', $parts)),
        );
    }

    /**
     * @param list<int> $indices
     */
    private function refused(RotationRun $run, Refusal $refusal, ?ScanReport $scan, array $indices, int $stillReadable): PurgeResult
    {
        return $this->results->stopped(
            status: PurgeStatus::Refused,
            runId: $run->id(),
            state: $run->state(),
            refusals: [$refusal],
            scan: $scan,
            purgedIndices: $indices,
            stillReadable: $stillReadable,
            embedded: $scan?->summary()->embedded() ?? 0,
            incompleteColumns: $scan?->summary()->incompleteColumns() ?? 0,
            withoutRowKey: $scan?->summary()->withoutRowKeyOnAny($indices) ?? 0,
        );
    }
}
