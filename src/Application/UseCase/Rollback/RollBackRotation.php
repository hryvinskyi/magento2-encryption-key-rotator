<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\RunPreflight;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StoreClaim;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptColumnValues;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\SystemValueReencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\VerifiedValuesOnIndices;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\WebTier\WebTierConfirmation;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\UnexpectedRingFingerprint;
use Psr\Clock\ClockInterface;

/**
 * Undoes a rotation from any state before it is purged, and finishes the job when run again after a crash
 * at any step, because every step reads the store as it is now instead of assuming the previous one ran.
 *
 * The target is the ring before the run: the rollback is done only when the deployment configuration
 * holds a ring with exactly the fingerprint the run recorded before it started. In order:
 * 0. `rolling_back` is recorded before anything else; from then on rotate, retire and purge refuse and
 *    only the rollback may continue the run. The file's ring must be one the run knows (a write it
 *    announced and that is in place is recorded). Then the checks (see {@see RunPreflight}), workers
 *    against the run's last key ring write: a process started before it still writes under the indices
 *    the run moved away from;
 * 1. every slot the run retired that holds a placeholder gets its kept key back, and the web tier is asked
 *    until it holds that ring: the next steps move values onto those keys, and a web tier still holding the
 *    placeholders would read them as empty. Not confirmed within the wait: the call stops, the run stays
 *    `rolling_back`;
 * 2. the forward journal is undone ({@see ForwardJournalReversal}): values get their bytes from before the
 *    run back, values the store rewrote under the new key move onto the key active before the run;
 * 3. every other value under the new key (written by the store meanwhile) moves onto the key active before
 *    the run, journaled as `back`; the new key is the one the run kept, so this works even once its slot
 *    is gone;
 * 4. the deployment configuration's values under the new key move the same way, by compare-and-swap per
 *    path; the backup of the file taken when the run started is never written back, since it would undo
 *    every change made to the file since;
 * 5. the configuration cache is cleaned, so the web tier repopulates it from values every ring reads;
 * 6. the store is scanned once more, and the new slot stays while anything still needs its key: a value
 *    that decrypts under it in the database (a conflict the passes could not settle) or in the
 *    deployment configuration, a whole ciphertext under it in a column without a row key (which the
 *    tool cannot move), or the deployed app/etc/config.php; embedded values and cut-short columns
 *    refuse too, unless the operator acknowledges them (recorded). The run stays `rolling_back`, and
 *    running rollback again once the cause is gone continues;
 * 7. the checks again, workers against now: removing the new slot takes away the active key of every
 *    process running at that moment, whenever it started, so any store process still running refuses
 *    it (unless workers are let run, which is recorded); then the new slot is removed by identity
 *    ({@see RollbackRingWriter});
 * 8. the web tier is asked until it holds the ring before the run;
 * 9. the values found under the new key once more (stragglers of processes that still held the new ring)
 *    move back with the kept key;
 * 10. the configuration cache is cleaned again, a final scan with the kept key counts what is left, and
 *    the run records `rolled_back`. The result carries the note on bearer tokens.
 *
 * While the store's claim names another run ({@see StoreClaim}), nothing is recorded and the call is
 * refused. With no unfinished run, a run that was rolled back last makes the call a no-op. Every refusal is a
 * result, never an exception; the call holds the run store's lock throughout.
 */
final class RollBackRotation
{
    public const BEARER_TOKEN_NOTE = 'Bearer tokens (REST and GraphQL) signed while the new key was the last key of the ring stop working now: the store signs and verifies them with the last key only. Their holders have to sign in again.';

    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $config,
        private readonly RunPreflight $preflight,
        private readonly StoreClaim $claim,
        private readonly RollbackRingWriter $ringWriter,
        private readonly WebTierConfirmation $webTier,
        private readonly ForwardJournalReversal $journal,
        private readonly ReencryptColumnValues $columns,
        private readonly SystemValueReencryption $systemValues,
        private readonly ConfigCacheCleaner $cache,
        private readonly ScanEncryptedData $scanner,
        private readonly VerifiedValuesOnIndices $remaining,
        private readonly KeyFactory $keys,
        private readonly ScanScopeFactory $scopes,
        private readonly RollBackResultFactory $results,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @throws RunLocked       when another process holds the run store's lock
     * @throws ConflictingRuns when the run store holds more than one unfinished run
     * @throws RoundTripFailed when a new value does not decrypt back to its plaintext; nothing of its batch is written
     */
    public function rollBack(RollBackRequest $request): RollBackResult
    {
        $this->runs->lock();
        try {
            $run = $this->runs->active();
            if ($run === null) {
                return $this->nothingToRollBack();
            }
            $claimed = $this->claim->heldByAnother($run->id());
            if ($claimed !== null) {
                return $this->refused($run, [$claimed], []);
            }
            if (!$run->isRollingBack()) {
                $this->progress->step(sprintf('Rolling back run %s from "%s"', $run->id()->toString(), $run->state()->value));
                $run->rollingBack($this->clock->now());
                $this->runs->save($run);
            } else {
                $this->progress->step(sprintf('Continuing the rollback of run %s', $run->id()->toString()));
            }

            return $this->undo($run, $request);
        } finally {
            $this->runs->unlock();
        }
    }

    private function undo(RotationRun $run, RollBackRequest $request): RollBackResult
    {
        $refusal = $this->ringWriter->reconcile($run);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], []);
        }
        $checks = $this->check($run, $request, $run->lastRingWriteAt());
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers());
        }
        $workers = $checks->workers();

        $refusal = $this->ringWriter->restoreRetired($run);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $workers);
        }
        $probe = null;
        if ($this->runs->keptKeys($run->id(), KeptKeyRole::Retired) !== []) {
            $probe = $this->awaitWebTier($run, $request);
            if ($probe !== null && !$probe->matches()) {
                return $this->awaiting($run, $workers, $probe);
            }
        }

        $scope = $this->scopes->create([]);
        $newIndex = $run->newIndex();
        $newKey = $this->keptNewKey($run);
        $back = null;
        if ($newIndex !== null) {
            $ring = $this->config->keyRing();
            $oldKey = $ring->slot($run->activeIndexBefore())?->key($this->keys);
            if ($newKey === null || $oldKey === null) {
                return $this->refused($run, [$this->refusals->create(RefusalReason::KeptMaterialMissing, sprintf(
                    'Run %s needs the new key it kept and the key of slot %d to move the values back, and lacks %s. Nothing more was written.',
                    $run->id()->toString(),
                    $run->activeIndexBefore(),
                    $newKey === null ? 'the new key' : sprintf('a key in slot %d', $run->activeIndexBefore()),
                ))], $workers, $probe);
            }
            $back = ['index' => $newIndex, 'new' => $newKey, 'old' => $oldKey];
        }

        $journal = null;
        $storeWritten = null;
        $rewritten = [];
        if ($back !== null) {
            $sources = [$back['index'] => $back['new']];
            $journal = $this->journal->revert($run->id(), $back['index'], $back['new'], $run->activeIndexBefore(), $back['old'], ScanEncryptedData::DEFAULT_BATCH_SIZE);
            $this->progress->step(sprintf('Moving the values the store wrote under key index %d onto key index %d', $back['index'], $run->activeIndexBefore()));
            $storeWritten = $this->columns->reencrypt($run->id(), Direction::Back, $sources, $run->activeIndexBefore(), $back['old'], $scope, ScanEncryptedData::DEFAULT_BATCH_SIZE);
            $changes = $this->moveSystemValues($run, $sources, $back['old']);
            if ($changes instanceof Refusal) {
                return $this->refused($run, [$changes], $workers, $probe);
            }
            $rewritten = $changes;
        }
        $this->cleanCache();

        $checks = $this->check($run, $request, $this->clock->now());
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers(), $probe);
        }
        $workers = $checks->workers();
        $refusal = $this->committedValuesUnderNewKey($run);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $workers, $probe);
        }
        $refusal = $this->valuesUnderNewKey($run, $request, $newKey);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $workers, $probe);
        }
        $refusal = $this->ringWriter->removeNewSlot($run, $newKey);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $workers, $probe);
        }
        $probe = $this->awaitWebTier($run, $request) ?? $probe;
        if ($probe !== null && !$probe->matches()) {
            return $this->awaiting($run, $workers, $probe);
        }

        $stragglers = null;
        $extraKeys = [];
        if ($back !== null) {
            $sources = [$back['index'] => $back['new']];
            $extraKeys = $sources;
            $this->progress->step(sprintf('Moving the values written under key index %d while the key ring changed', $back['index']));
            $stragglers = $this->columns->reencrypt($run->id(), Direction::Back, $sources, $run->activeIndexBefore(), $back['old'], $scope, ScanEncryptedData::DEFAULT_BATCH_SIZE);
            $changes = $this->moveSystemValues($run, $sources, $back['old']);
            if ($changes instanceof Refusal) {
                return $this->refused($run, [$changes], $workers, $probe);
            }
            $rewritten = [...$rewritten, ...$changes];
        }
        $cleaned = $this->cleanCache();

        $this->progress->step('Scanning what remains under the new key');
        $scan = $this->scanner->scan($scope, $extraKeys, ScanEncryptedData::DEFAULT_BATCH_SIZE);
        try {
            $run->rolledBack($this->config->keyRing()->fingerprint(), $this->clock->now());
        } catch (UnexpectedRingFingerprint $changed) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::RingChanged, sprintf(
                '%s Another writer changed the deployment configuration during the rollback; run rollback again.',
                $changed->getMessage(),
            ))], $workers, $probe);
        }
        $this->runs->save($run);

        return $this->results->rolledBack(
            status: RollBackStatus::RolledBack,
            runId: $run->id(),
            state: $run->state(),
            rolledBackFrom: $run->rolledBackFrom(),
            workers: $workers,
            probe: $probe,
            journal: $journal,
            storeWritten: $storeWritten,
            stragglers: $stragglers,
            rewrittenSystemPaths: $rewritten,
            cacheClean: $cleaned,
            scan: $scan,
            ringFingerprint: $run->ringFingerprint(),
            bearerTokenNote: $newIndex === null ? null : self::BEARER_TOKEN_NOTE,
        );
    }

    /**
     * Moves the deployment configuration's values under the new key onto the key active before the run,
     * in one compare-and-swap write of the file with the ring it holds now.
     *
     * @param array<int, Key> $sources the new index => the kept new key
     *
     * @return list<string>|Refusal the paths rewritten, or why nothing was written
     */
    private function moveSystemValues(RotationRun $run, array $sources, Key $oldKey): array|Refusal
    {
        $ring = $this->config->keyRing();
        try {
            $changes = $this->systemValues->reencrypt($sources, $run->activeIndexBefore(), $oldKey, $ring, $ring->fingerprint());
        } catch (StaleDeploymentConfig $stale) {
            return $this->refusals->create(RefusalReason::DeploymentConfigChanged, sprintf(
                '%s Run rollback again to move the deployment configuration values.',
                $stale->getMessage(),
            ));
        }

        return array_map(static fn(SystemValueChange $change): string => $change->pathString(), $changes);
    }

    /**
     * Refuses removing the new slot while the deployed app/etc/config.php still holds values under it: that
     * file is deployed, never written by the tool, so once the slot is gone nothing could read them again.
     */
    private function committedValuesUnderNewKey(RotationRun $run): ?Refusal
    {
        $newIndex = $run->newIndex();
        if ($newIndex === null || $this->config->keyRing()->slot($newIndex) === null) {
            return null;
        }
        $paths = [];
        foreach ($this->config->committedSystemValues() as $value) {
            if ($value->ciphertext()->keyIndex() === $newIndex) {
                $paths[] = $value->pathString();
            }
        }
        if ($paths === []) {
            return null;
        }

        return $this->refusals->create(RefusalReason::CommittedValuesOnRemovedKey, sprintf(
            'app/etc/config.php holds values under key index %d, which the rollback is about to remove: %s. Deploy that file with those values encrypted under key index %d, then run rollback again. The new key is still in place.',
            $newIndex,
            implode(', ', $paths),
            $run->activeIndexBefore(),
        ));
    }

    /**
     * Refuses removing the new slot while the store still holds values only its key reads: once the slot
     * is gone nothing could read them again. Embedded values and cut-short columns may be such values, so
     * they refuse unless the operator acknowledged them, which the run records.
     */
    private function valuesUnderNewKey(RotationRun $run, RollBackRequest $request, ?Key $newKey): ?Refusal
    {
        $newIndex = $run->newIndex();
        if ($newIndex === null || $newKey === null || $this->config->keyRing()->slot($newIndex) === null) {
            return null;
        }

        $this->progress->step(sprintf('Scanning for values still under key index %d before removing it', $newIndex));
        $scan = $this->scanner->scan($this->scopes->create([]), [$newIndex => $newKey], ScanEncryptedData::DEFAULT_BATCH_SIZE);
        $summary = $scan->summary();
        $obstacles = [];
        $where = $this->remaining->describe($scan, [$newIndex]);
        if ($where !== '') {
            $obstacles[] = sprintf('values remain under key index %d: %s', $newIndex, $where);
        }
        if ($summary->hasUnjudgedValues()) {
            if ($request->acceptsEmbedded()) {
                $run->overridden(RunOverride::AcceptEmbedded, $this->clock->now());
                $this->runs->save($run);
            } else {
                $obstacles[] = sprintf(
                    '%d embedded values and %d columns whose scan was cut short are not acknowledged (--accept-embedded)',
                    $summary->embedded(),
                    $summary->incompleteColumns(),
                );
            }
        }
        if ($obstacles === []) {
            return null;
        }

        return $this->refusals->create(RefusalReason::RollbackBlocked, sprintf(
            'Run %s cannot remove the new key yet: %s. The new key is still in place. Move those values onto the key active before the run (or acknowledge the embedded ones), then run rollback again.',
            $run->id()->toString(),
            implode('; ', $obstacles),
        ));
    }

    /**
     * Asks the web tier until it holds the ring the file holds now; null when the probe is skipped (which
     * is recorded on the run).
     */
    private function awaitWebTier(RotationRun $run, RollBackRequest $request): ?ProbeOutcome
    {
        if ($request->probeSettings()->isSkipped()) {
            $run->overridden(RunOverride::SkipWebProbe, $this->clock->now());
            $this->runs->save($run);

            return null;
        }

        return $this->webTier->await($this->config->keyRing(), $request->probeSettings());
    }

    private function cleanCache(): CacheCleanOutcome
    {
        $this->progress->step('Cleaning the configuration cache');
        $outcome = $this->cache->clean();
        if (!$outcome->cleaned()) {
            $this->progress->warn(sprintf(
                'The configuration cache was not cleaned: %s Clean it now, so the web tier drops values cached under the new key.',
                $outcome->reason(),
            ));
        }

        return $outcome;
    }

    private function keptNewKey(RotationRun $run): ?Key
    {
        foreach ($this->runs->keptKeys($run->id(), KeptKeyRole::Added) as $slot) {
            if ($slot->index() === $run->newIndex()) {
                return $slot->key($this->keys);
            }
        }

        return null;
    }

    /**
     * The checks before a ring write of the rollback, against the ring the file holds now (already matched
     * against the run) and the moment a running process must have started after. Waived checks are
     * recorded on the run.
     */
    private function check(RotationRun $run, RollBackRequest $request, ?\DateTimeImmutable $startedAfter): PreflightResult
    {
        $checks = $this->preflight->check(
            $this->config->keyRing()->fingerprint(),
            $startedAfter,
            $request->ignoresWorkers(),
            $request->allowsOtherUser(),
            $request->probeSettings(),
        );
        if ($checks->passed() && $checks->waived() !== []) {
            $now = $this->clock->now();
            foreach ($checks->waived() as $override) {
                $run->overridden($override, $now);
            }
            $this->runs->save($run);
        }

        return $checks;
    }

    private function nothingToRollBack(): RollBackResult
    {
        $latest = $this->runs->latest();
        if ($latest !== null && $latest->state() === RunState::RolledBack) {
            return $this->results->stopped(
                status: RollBackStatus::AlreadyRolledBack,
                runId: $latest->id(),
                state: $latest->state(),
                rolledBackFrom: $latest->rolledBackFrom(),
                refusals: [],
                workers: [],
                probe: null,
                ringFingerprint: $latest->ringFingerprint(),
            );
        }

        return $this->refused(null, [$this->refusals->create(
            RefusalReason::NoRun,
            'No rotation is in progress; there is nothing to roll back.',
        )], []);
    }

    /**
     * @param list<RunningProcess> $workers
     */
    private function awaiting(RotationRun $run, array $workers, ProbeOutcome $probe): RollBackResult
    {
        return $this->results->stopped(
            status: RollBackStatus::AwaitingWebTier,
            runId: $run->id(),
            state: $run->state(),
            rolledBackFrom: $run->rolledBackFrom(),
            refusals: [],
            workers: $workers,
            probe: $probe,
            ringFingerprint: $run->ringFingerprint(),
        );
    }

    /**
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    private function refused(?RotationRun $run, array $refusals, array $workers, ?ProbeOutcome $probe = null): RollBackResult
    {
        return $this->results->stopped(
            status: RollBackStatus::Refused,
            runId: $run?->id(),
            state: $run?->state(),
            rolledBackFrom: $run?->rolledBackFrom(),
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            ringFingerprint: $run?->ringFingerprint(),
        );
    }
}
