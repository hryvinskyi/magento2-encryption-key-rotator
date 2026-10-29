<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\KeptMaterialConflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\RunPreflight;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StoreClaim;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptColumnValues;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
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
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RetireRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\UnexpectedRingFingerprint;
use Psr\Clock\ClockInterface;

/**
 * Retires the keys a rotation moved away from: replaces each of them by a placeholder in the key ring,
 * once no stored value needs them, without leaving a value on a key the web tier can no longer read for
 * longer than one straggler pass.
 *
 * The moved indices are the key that was active before the run and every usable key below it. A
 * `reencrypted` run goes, in order:
 * 1. checks (see {@see RunPreflight}), workers against the rotation's key ring write: a process started
 *    before it still holds the ring without the new key and keeps writing under the old indices;
 * 2. stragglers: values written under the moved indices since the re-encryption move onto the active
 *    key (database and deployment configuration); when any moved, the configuration cache is cleaned
 *    again, and a failed clean refuses unless the operator cleaned it by hand;
 * 3. a fresh scan, recorded on the run; the retirement is refused while values remain on the moved
 *    indices (database, columns without a row key, deployment configuration or committed
 *    configuration; acknowledging embedded values never waives them), while embedded values or
 *    cut-short columns are unacknowledged, or while the cache was not cleaned after the last
 *    re-encryption;
 * 4. the placeholder ring is announced and written ({@see PlaceholderRingWriter}): the replaced keys and
 *    the placeholders are kept first, then `retire_pending` is recorded, then the file is written;
 * 5. the web tier is asked until it holds the placeholder ring, or the wait is spent: then the run waits
 *    at `retire_pending` and the same command resumes it (unless the probe is skipped, which is recorded);
 * 6. stragglers written while the ring changed move onto the active key with the kept keys (the run
 *    still holds them although the file no longer does), then the configuration cache is cleaned, so the
 *    cache never keeps a value on a retired index; a final scan with the kept keys counts what is left,
 *    and the run records `retired`.
 *
 * Running the command again on a `retire_pending` run resumes it, reading the deployment configuration
 * as it is now: the ring before the retirement is written again with the kept placeholders, the ring with
 * them continues at the probe, any other ring is refused naming both. A run that is rolling back is
 * refused, and so is any run while the store's claim names another run ({@see StoreClaim}). Every refusal is a result, never an exception; the call holds the run store's lock throughout.
 */
final class RetireOldKeys
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $config,
        private readonly RunPreflight $preflight,
        private readonly StoreClaim $claim,
        private readonly PlaceholderRingWriter $placeholders,
        private readonly WebTierConfirmation $webTier,
        private readonly ScanEncryptedData $scanner,
        private readonly ReencryptColumnValues $columns,
        private readonly SystemValueReencryption $systemValues,
        private readonly ConfigCacheCleaner $cache,
        private readonly VerifiedValuesOnIndices $remaining,
        private readonly KeyFactory $keys,
        private readonly ScanScopeFactory $scopes,
        private readonly RetireResultFactory $results,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @throws RunLocked            when another process holds the run store's lock
     * @throws ConflictingRuns      when the run store holds more than one unfinished run
     * @throws KeptMaterialConflict when the run keeps other material than the retirement would keep
     * @throws RoundTripFailed      when a new value does not decrypt back to its plaintext; nothing of its batch is written
     */
    public function retire(RetireRequest $request): RetireResult
    {
        $this->runs->lock();
        try {
            $run = $this->runs->active();
            if ($run === null) {
                return $this->refused(null, [$this->refusals->create(
                    RefusalReason::NoRun,
                    'No rotation is in progress; there are no old keys to retire.',
                )], []);
            }
            $claimed = $this->claim->heldByAnother($run->id());
            if ($claimed !== null) {
                return $this->refused($run, [$claimed], []);
            }

            return match ($run->state()) {
                RunState::Reencrypted => $this->start($run, $request),
                RunState::RetirePending => $this->resume($run, $request),
                RunState::RollingBack => $this->refused($run, [$this->refusals->create(
                    RefusalReason::RollbackInProgress,
                    sprintf('Run %s is rolling back; only the rollback may continue it. Run rollback again.', $run->id()->toString()),
                )], []),
                default => $this->refused($run, [$this->refusals->create(
                    RefusalReason::StateDoesNotAllow,
                    sprintf(
                        'Run %s is "%s"; the old keys are retired once the values moved onto the new key (state "%s").',
                        $run->id()->toString(),
                        $run->state()->value,
                        RunState::Reencrypted->value,
                    ),
                )], []),
            };
        } finally {
            $this->runs->unlock();
        }
    }

    private function start(RotationRun $run, RetireRequest $request): RetireResult
    {
        $checks = $this->check($request, $run->ringFingerprint(), $run->lastRingWriteAt());
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers());
        }
        $this->recordWaived($run, $checks);
        $this->runs->save($run);

        $ring = $this->config->keyRing();
        $scope = $this->scopes->create([]);
        $newIndex = $this->newIndex($run);
        $target = $ring->active($this->keys);

        $this->progress->step(sprintf('Moving the values written under key indices %s since the re-encryption', implode(', ', $run->movedIndices())));
        try {
            $stragglers = $this->columns->reencrypt($run->id(), Direction::Forward, $this->movedKeys($run, $ring), $newIndex, $target, $scope, ScanEncryptedData::DEFAULT_BATCH_SIZE);
            $changes = $this->systemValues->reencrypt($this->movedKeys($run, $ring), $newIndex, $target, $ring, $run->ringFingerprint());
        } catch (StaleDeploymentConfig $stale) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::DeploymentConfigChanged, $stale->getMessage())], $checks->workers());
        }

        $cleaned = $run->configCacheCleaned();
        $cacheRefusal = null;
        if ($stragglers->appliedTotal() > 0 || $changes !== []) {
            $this->progress->step('Cleaning the configuration cache after moving the stragglers');
            $outcome = $this->cache->clean();
            $cleaned = $outcome->cleaned();
            if (!$cleaned && !$request->cacheCleanedManually()) {
                $cacheRefusal = $this->refusals->create(RefusalReason::CacheNotCleaned, sprintf(
                    'Values moved onto the new key, but the configuration cache was not cleaned: %s Clean it, then run retire again with --cache-cleaned-manually.',
                    $outcome->reason(),
                ));
            }
        }

        $this->progress->step('Scanning what remains on the old keys');
        $scan = $this->scanner->scan($scope, [], ScanEncryptedData::DEFAULT_BATCH_SIZE);
        $run->reencrypted($scan->summary(), $cleaned, $this->clock->now());
        $this->runs->save($run);
        if ($cacheRefusal !== null) {
            return $this->refused($run, [$cacheRefusal], $checks->workers(), $scan);
        }

        try {
            $intended = $this->placeholders->announce($run, $ring, $this->overrides($run, $scan, $request));
        } catch (RetireRefused $refused) {
            $where = $this->remaining->describe($scan, $run->movedIndices());

            return $this->refused($run, [$this->refusals->create(
                RefusalReason::RetireBlocked,
                $where === '' ? $refused->getMessage() : sprintf('%s Values remain: %s.', $refused->getMessage(), $where),
            )], $checks->workers(), $scan);
        } catch (KeyRingChangeRefused $refused) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::StateDoesNotAllow, $refused->getMessage())], $checks->workers(), $scan);
        }

        $refusal = $this->placeholders->write($run, $intended);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $checks->workers(), $scan);
        }

        return $this->afterRingWrite($run, $request, $checks->workers(), $stragglers);
    }

    private function resume(RotationRun $run, RetireRequest $request): RetireResult
    {
        $this->progress->step(sprintf('Resuming the retirement of run %s', $run->id()->toString()));
        $checks = $this->check($request, null, $run->lastRingWriteAt());
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers());
        }
        $this->recordWaived($run, $checks);
        $this->runs->save($run);

        $refusal = $this->placeholders->resume($run);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $checks->workers());
        }

        return $this->afterRingWrite($run, $request, $checks->workers(), null);
    }

    /**
     * Steps 5 and 6: the probe, the stragglers moved with the kept keys, the cache clean, `retired`.
     *
     * @param list<RunningProcess> $workers
     */
    private function afterRingWrite(RotationRun $run, RetireRequest $request, array $workers, ?ReencryptionOutcome $stragglersBefore): RetireResult
    {
        $ring = $this->config->keyRing();
        $probe = null;
        if ($request->probeSettings()->isSkipped()) {
            $run->overridden(RunOverride::SkipWebProbe, $this->clock->now());
            $this->runs->save($run);
        } else {
            $probe = $this->webTier->await($ring, $request->probeSettings());
            if (!$probe->matches()) {
                return $this->results->stopped(
                    status: RetireStatus::AwaitingWebTier,
                    runId: $run->id(),
                    state: $run->state(),
                    refusals: [],
                    workers: $workers,
                    probe: $probe,
                    scan: null,
                    ringFingerprint: $ring->fingerprint(),
                );
            }
        }

        $kept = $this->keptKeys($run);
        if ($kept === []) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::KeptMaterialMissing, sprintf(
                'Run %s keeps none of the keys it retired; the stragglers cannot be moved. Nothing more was written.',
                $run->id()->toString(),
            ))], $workers, null, $probe);
        }
        $newIndex = $this->newIndex($run);
        $target = $ring->active($this->keys);
        $scope = $this->scopes->create([]);

        $this->progress->step('Moving the values written under the retired keys while the key ring changed, with the kept keys');
        try {
            $stragglersAfter = $this->columns->reencrypt($run->id(), Direction::Forward, $kept, $newIndex, $target, $scope, ScanEncryptedData::DEFAULT_BATCH_SIZE);
            $changes = $this->systemValues->reencrypt($kept, $newIndex, $target, $ring, $ring->fingerprint());
        } catch (StaleDeploymentConfig $stale) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::DeploymentConfigChanged, sprintf(
                '%s Run retire again to move the remaining values.',
                $stale->getMessage(),
            ))], $workers, null, $probe);
        }

        $cleaned = $this->cleanCache();

        $this->progress->step('Scanning what remains on the retired keys');
        $scan = $this->scanner->scan($scope, $kept, ScanEncryptedData::DEFAULT_BATCH_SIZE);
        try {
            $run->retired($this->config->keyRing()->fingerprint(), $this->clock->now());
        } catch (UnexpectedRingFingerprint $changed) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::RingChanged, sprintf(
                '%s Another writer changed the deployment configuration after the retirement was written.',
                $changed->getMessage(),
            ))], $workers, $scan, $probe);
        }
        $this->runs->save($run);

        return $this->results->retired(
            status: RetireStatus::Retired,
            runId: $run->id(),
            state: $run->state(),
            workers: $workers,
            probe: $probe,
            scan: $scan,
            stragglersBeforeWrite: $stragglersBefore,
            stragglersAfterWrite: $stragglersAfter,
            rewrittenSystemPaths: array_map(static fn(SystemValueChange $change): string => $change->pathString(), $changes),
            cacheClean: $cleaned,
            retiredIndices: array_keys($kept),
            ringFingerprint: $run->ringFingerprint(),
        );
    }

    private function cleanCache(): CacheCleanOutcome
    {
        $this->progress->step('Cleaning the configuration cache');
        $outcome = $this->cache->clean();
        if (!$outcome->cleaned()) {
            $this->progress->warn(sprintf(
                'The configuration cache was not cleaned: %s Clean it now, so the web tier drops values cached under the retired keys.',
                $outcome->reason(),
            ));
        }

        return $outcome;
    }

    /**
     * The checks the operator waived and that do waive something for this run.
     *
     * @return list<RunOverride>
     */
    private function overrides(RotationRun $run, ScanReport $scan, RetireRequest $request): array
    {
        $overrides = [];
        if ($request->acceptsEmbedded() && $scan->summary()->hasUnjudgedValues()) {
            $overrides[] = RunOverride::AcceptEmbedded;
        }
        if ($request->cacheCleanedManually() && !$run->configCacheCleaned()) {
            $overrides[] = RunOverride::CacheCleanedManually;
        }

        return $overrides;
    }

    /**
     * @return array<int, Key> moved index => its key in the ring, for the indices whose slot still holds one
     */
    private function movedKeys(RotationRun $run, KeyRing $ring): array
    {
        $keys = [];
        foreach ($run->movedIndices() as $index) {
            $key = $ring->slot($index)?->key($this->keys);
            if ($key !== null) {
                $keys[$index] = $key;
            }
        }

        return $keys;
    }

    /**
     * @return array<int, Key> retired index => the key kept for it
     */
    private function keptKeys(RotationRun $run): array
    {
        $keys = [];
        foreach ($this->runs->keptKeys($run->id(), KeptKeyRole::Retired) as $slot) {
            $key = $slot->key($this->keys);
            if ($key !== null) {
                $keys[$slot->index()] = $key;
            }
        }

        return $keys;
    }

    private function newIndex(RotationRun $run): int
    {
        return $run->newIndex() ?? throw new \LogicException(sprintf('Run %s has announced no new key.', $run->id()->toString()));
    }

    private function check(RetireRequest $request, ?string $expectedRingFingerprint, ?\DateTimeImmutable $ringWrittenAt): PreflightResult
    {
        return $this->preflight->check(
            $expectedRingFingerprint,
            $ringWrittenAt,
            $request->ignoresWorkers(),
            $request->allowsOtherUser(),
            $request->probeSettings(),
        );
    }

    private function recordWaived(RotationRun $run, PreflightResult $checks): void
    {
        $now = $this->clock->now();
        foreach ($checks->waived() as $override) {
            $run->overridden($override, $now);
        }
    }

    /**
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    private function refused(?RotationRun $run, array $refusals, array $workers, ?ScanReport $scan = null, ?ProbeOutcome $probe = null): RetireResult
    {
        return $this->results->stopped(
            status: RetireStatus::Refused,
            runId: $run?->id(),
            state: $run?->state(),
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            scan: $scan,
            ringFingerprint: $run?->ringFingerprint(),
        );
    }
}
