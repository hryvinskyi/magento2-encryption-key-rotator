<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\PreflightResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\RunPreflight;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight\StoreClaim;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\WebTier\WebTierConfirmation;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingChangeRefused;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Psr\Clock\ClockInterface;

/**
 * Rotates the store's encryption key: appends a new key to the ring and moves every value under the
 * previous keys onto it, without ever making a key the web tier still needs unreadable.
 *
 * A new rotation goes, in order:
 * 1. checks (see {@see RunPreflight}), workers against now; then a baseline probe: the web tier must hold
 *    the current ring, which proves the probe reaches it before anything is written (unless skipped);
 * 2. a scan of what will move (every column: a rotation never leaves one out);
 * 3. the run claims the store ({@see StoreClaim}), refused while another run of any state directory
 *    holds it; then it starts, with a copy of the deployment configuration in its directory, and the
 *    journal is made ready;
 * 4. the key is appended through a write announced beforehand ({@see NewKeyAppender});
 * 5. the web tier is asked until it holds the new ring, or the wait is spent: then the run waits at
 *    `key_added` and nothing further runs (unless the probe is skipped, which is recorded);
 * 6. the checks again, workers against the key ring write: a process started before it still holds the
 *    ring without the new key; then the values move ({@see RotationReencryption}).
 *
 * Running the command again resumes the active run where it stands, reading the deployment configuration
 * as it is now: `started` and `key_pending` continue at the key write, `key_added` at the probe,
 * `web_confirmed` and `reencrypted` at the re-encryption (a further pass touches only values still under
 * an old key); a resumed run claims the store again, so another run holding it refuses the resume. A run
 * that is rolling back, retiring its old keys or retired is refused. A dry run scans and reports the plan
 * without taking the lock, starting a run or writing anything; another run holding the store is among
 * the refusals it lists. When a probe transport is chosen it also asks the web tier once, as the baseline
 * probe of a new rotation would, so a probe that cannot reach PHP-FPM is a refusal of the plan rather than
 * of the real run; the one-off probe file it places is removed again.
 *
 * Every refusal is a result, never an exception; the call holds the run store's lock throughout.
 */
final class RotateKey
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $config,
        private readonly RunPreflight $preflight,
        private readonly StoreClaim $claim,
        private readonly RunIdGenerator $ids,
        private readonly NewKeyAppender $appender,
        private readonly WebTierConfirmation $webTier,
        private readonly ScanEncryptedData $scanner,
        private readonly RotationReencryption $reencryption,
        private readonly JournalSchema $journal,
        private readonly KeyFactory $keys,
        private readonly ScanScopeFactory $scopes,
        private readonly RotateResultFactory $results,
        private readonly RefusalFactory $refusals,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @throws RunLocked       when another process holds the run store's lock
     * @throws ConflictingRuns when the run store holds more than one unfinished run
     */
    public function rotate(RotateRequest $request): RotateResult
    {
        if ($request->isDryRun()) {
            return $this->plan($request);
        }

        $this->runs->lock();
        try {
            $run = $this->runs->active();

            return $run === null ? $this->start($request) : $this->resume($run, $request);
        } finally {
            $this->runs->unlock();
        }
    }

    private function plan(RotateRequest $request): RotateResult
    {
        try {
            $ring = $this->config->keyRing();
        } catch (InvalidKeyRing|InvalidKey $unusable) {
            return $this->refused(null, [$this->refusals->create(RefusalReason::RingUnusable, $unusable->getMessage())], []);
        }
        $checks = $this->check($request, null, $this->clock->now());
        $refusals = $checks->refusals();
        $claimed = $this->claim->heldByAnother($this->runs->active()?->id());
        if ($claimed !== null) {
            $refusals[] = $claimed;
        }
        $probe = null;
        $settings = $request->probeSettings();
        if (!$settings->isSkipped() && $settings->transport() !== null) {
            $probe = $this->webTier->once($ring);
            if (!$probe->matches()) {
                $refusals[] = $this->baselineProbeFailed($ring, $probe);
            }
        }
        $this->progress->step('Scanning the values a rotation would move');
        $scan = $this->scanner->scan($this->scopes->create([]), [], $request->batchSize());
        $sources = [...$ring->usableOldIndices(), $ring->activeIndex()];

        return $this->results->dryRun(
            status: RotateStatus::DryRun,
            scan: $scan,
            refusals: $refusals,
            workers: $checks->workers(),
            probe: $probe,
            sourceIndices: $sources,
            newIndex: $ring->activeIndex() + 1,
            ringFingerprint: $ring->fingerprint(),
        );
    }

    private function start(RotateRequest $request): RotateResult
    {
        $checks = $this->check($request, null, $this->clock->now());
        if (!$checks->passed()) {
            return $this->refused(null, $checks->refusals(), $checks->workers());
        }
        $ring = $this->config->keyRing();
        try {
            $key = $this->appender->candidate($ring, $request->rawKey());
        } catch (InvalidKey|KeyRingChangeRefused $rejected) {
            return $this->refused(null, [$this->refusals->create(RefusalReason::KeyRejected, $rejected->getMessage())], $checks->workers());
        }

        $probe = null;
        if (!$request->probeSettings()->isSkipped()) {
            $probe = $this->webTier->once($ring);
            if (!$probe->matches()) {
                return $this->refused(null, [$this->baselineProbeFailed($ring, $probe)], $checks->workers(), $probe);
            }
        }

        $this->progress->step('Scanning the values the rotation will move');
        $this->scanner->scan($this->scopes->create([]), [], $request->batchSize());
        $id = $this->ids->next();
        $refusal = $this->claim->claim($id);
        if ($refusal !== null) {
            return $this->refused(null, [$refusal], $checks->workers(), $probe);
        }
        try {
            $run = $this->appender->start($id, $ring, $checks->waived());
        } catch (\Throwable $failure) {
            // A run that never started must not keep the store from the next one.
            $this->claim->release($id);

            throw $failure;
        }
        $this->journal->ensure();

        return $this->advance($run, $request, $key, $checks->workers(), $probe);
    }

    private function resume(RotationRun $run, RotateRequest $request): RotateResult
    {
        $refusal = $this->stateRefusal($run);
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], []);
        }
        $this->progress->step(sprintf('Resuming run %s from "%s"', $run->id()->toString(), $run->state()->value));

        $beforeKeyWrite = $this->isBeforeKeyWrite($run);
        $checks = $this->check(
            $request,
            $beforeKeyWrite ? null : $run->ringFingerprint(),
            $beforeKeyWrite ? $this->clock->now() : null,
        );
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers());
        }
        $refusal = $this->claim->claim($run->id());
        if ($refusal !== null) {
            return $this->refused($run, [$refusal], $checks->workers());
        }
        $this->recordWaived($run, $checks);

        $key = null;
        if ($request->rawKey() !== null) {
            try {
                $key = $this->keys->create($request->rawKey());
            } catch (InvalidKey $rejected) {
                return $this->refused($run, [$this->refusals->create(RefusalReason::KeyRejected, $rejected->getMessage())], $checks->workers());
            }
        }

        return $this->advance($run, $request, $key, $checks->workers(), null);
    }

    /**
     * Takes the run from wherever it stands to `reencrypted`, or as far as the store allows.
     *
     * @param list<RunningProcess> $workers
     */
    private function advance(RotationRun $run, RotateRequest $request, ?Key $key, array $workers, ?ProbeOutcome $probe): RotateResult
    {
        if ($this->isBeforeKeyWrite($run)) {
            $refusal = $this->appender->append($run, $key);
            if ($refusal !== null) {
                return $this->refused($run, [$refusal], $workers, $probe);
            }
        }

        if ($run->state() === RunState::KeyAdded) {
            $ring = $this->config->keyRing();
            if ($ring->fingerprint() !== $run->ringFingerprint()) {
                return $this->refused($run, [$this->ringChanged($run, $ring->fingerprint())], $workers, $probe);
            }
            $skipped = $request->probeSettings()->isSkipped();
            if (!$skipped) {
                $probe = $this->webTier->await($ring, $request->probeSettings());
                if (!$probe->matches()) {
                    return $this->results->stopped(
                        status: RotateStatus::AwaitingWebTier,
                        runId: $run->id(),
                        state: $run->state(),
                        refusals: [],
                        workers: $workers,
                        probe: $probe,
                        keyAppended: true,
                        ringFingerprint: $run->ringFingerprint(),
                    );
                }
            }
            $run->webConfirmed($skipped, $this->clock->now());
            $this->runs->save($run);
        }

        $checks = $this->check($request, $run->ringFingerprint(), $run->lastRingWriteAt());
        if (!$checks->passed()) {
            return $this->refused($run, $checks->refusals(), $checks->workers(), $probe);
        }
        $this->recordWaived($run, $checks);
        $this->runs->save($run);

        try {
            return $this->reencryption->complete($run, $this->config->keyRing(), $request, $checks->workers(), $probe);
        } catch (StaleDeploymentConfig $stale) {
            return $this->refused($run, [$this->refusals->create(RefusalReason::DeploymentConfigChanged, sprintf(
                '%s The database values were moved; run the command again to move the deployment configuration values.',
                $stale->getMessage(),
            ))], $checks->workers(), $probe);
        }
    }

    private function check(RotateRequest $request, ?string $expectedRingFingerprint, ?\DateTimeImmutable $ringWrittenAt): PreflightResult
    {
        return $this->preflight->check(
            $expectedRingFingerprint,
            $ringWrittenAt,
            $request->ignoresWorkers(),
            $request->allowsOtherUser(),
            $request->probeSettings(),
        );
    }

    private function baselineProbeFailed(KeyRing $ring, ProbeOutcome $probe): Refusal
    {
        return $this->refusals->create(RefusalReason::BaselineProbeFailed, sprintf(
            'The web tier did not confirm the current key ring %s (%s): %s Nothing was written.',
            $ring->fingerprint(),
            $probe->status()->value,
            $probe->reason(),
        ));
    }

    private function recordWaived(RotationRun $run, PreflightResult $checks): void
    {
        $now = $this->clock->now();
        foreach ($checks->waived() as $override) {
            $run->overridden($override, $now);
        }
    }

    private function stateRefusal(RotationRun $run): ?Refusal
    {
        $id = $run->id()->toString();

        return match ($run->state()) {
            RunState::RollingBack => $this->refusals->create(
                RefusalReason::RollbackInProgress,
                sprintf('Run %s is rolling back; only the rollback may continue it. Run rollback again.', $id),
            ),
            RunState::RetirePending => $this->refusals->create(
                RefusalReason::RunPastRotation,
                sprintf('Run %s was interrupted while retiring its old keys; run retire again, or rollback.', $id),
            ),
            RunState::Retired => $this->refusals->create(
                RefusalReason::RunPastRotation,
                sprintf('Run %s retired its old keys; purge it before the next rotation, or roll it back.', $id),
            ),
            default => null,
        };
    }

    private function ringChanged(RotationRun $run, string $found): Refusal
    {
        return $this->refusals->create(RefusalReason::RingChanged, sprintf(
            'The deployment configuration holds the key ring %s, but run %s recorded %s: another writer changed it. Nothing was written.',
            $found,
            $run->id()->toString(),
            $run->ringFingerprint(),
        ));
    }

    private function isBeforeKeyWrite(RotationRun $run): bool
    {
        return $run->state() === RunState::Started || $run->state() === RunState::KeyPending;
    }

    /**
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    private function refused(?RotationRun $run, array $refusals, array $workers, ?ProbeOutcome $probe = null): RotateResult
    {
        return $this->results->stopped(
            status: RotateStatus::Refused,
            runId: $run?->id(),
            state: $run?->state(),
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            keyAppended: $run !== null && !$this->isBeforeKeyWrite($run),
            ringFingerprint: $run?->ringFingerprint(),
        );
    }
}
