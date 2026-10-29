<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptColumnValues;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\SystemValueReencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\RoundTripFailed;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Psr\Clock\ClockInterface;

/**
 * Moves a rotation's values onto its new key once the web tier holds it, then records the pass.
 *
 * The values that move are those under the key that was active before the run and under every usable
 * key below it. In order:
 * 1. the database values of every column, by compare-and-swap, journaled;
 * 2. the deployment configuration's `system` values, in one compare-and-swap write of the file with the
 *    ring the run recorded;
 * 3. the configuration cache is cleaned, so the web tier reloads the rewritten values (a failure is a
 *    warning, recorded on the run, since retiring the old keys checks it);
 * 4. a rescan, whose summary the run records with the state `reencrypted`.
 *
 * Only values still under an old index are touched, so another pass after an interruption, or later to
 * catch stragglers, is safe.
 */
final class RotationReencryption
{
    public function __construct(
        private readonly ReencryptColumnValues $columns,
        private readonly SystemValueReencryption $systemValues,
        private readonly ConfigCacheCleaner $cache,
        private readonly ScanEncryptedData $scanner,
        private readonly RunStore $runs,
        private readonly KeyFactory $keys,
        private readonly ScanScopeFactory $scopes,
        private readonly RotateResultFactory $results,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @param RotationRun          $run     a run whose web tier holds the new key (`web_confirmed` or `reencrypted`)
     * @param KeyRing              $ring    the ring the deployment configuration holds, the one the run recorded
     * @param RotateRequest        $request the operator's request
     * @param list<RunningProcess> $workers the processes let run, for the result
     * @param ProbeOutcome|null    $probe   the web tier answer of this call, for the result
     *
     * @throws StaleDeploymentConfig      when the deployment configuration changed before its values were written
     * @throws DeploymentConfigUnreadable when the deployment configuration cannot be read, written or verified
     * @throws RoundTripFailed            when a new value does not decrypt back to its plaintext
     */
    public function complete(RotationRun $run, KeyRing $ring, RotateRequest $request, array $workers, ?ProbeOutcome $probe): RotateResult
    {
        $newIndex = $run->newIndex() ?? throw new \LogicException(sprintf('Run %s has announced no new key.', $run->id()->toString()));
        $target = $ring->slot($newIndex)?->key($this->keys)
            ?? throw new \LogicException(sprintf('The key ring holds no usable key in slot %d.', $newIndex));
        $sources = $this->sources($run, $ring);

        $this->progress->step(sprintf('Re-encrypting the database values of key indices %s under key index %d', implode(', ', array_keys($sources)), $newIndex));
        $scope = $this->scopes->create([]);
        $moved = $this->columns->reencrypt($run->id(), Direction::Forward, $sources, $newIndex, $target, $scope, $request->batchSize());

        $this->progress->step('Re-encrypting the encrypted values of the deployment configuration');
        $changes = $this->systemValues->reencrypt($sources, $newIndex, $target, $ring, $run->ringFingerprint());

        $this->progress->step('Cleaning the configuration cache');
        $cleaned = $this->cache->clean();
        if (!$cleaned->cleaned()) {
            $this->progress->warn(sprintf('The configuration cache was not cleaned: %s Clean it before retiring the old keys.', $cleaned->reason()));
        }

        $this->progress->step('Scanning what remains');
        $rescan = $this->scanner->scan($scope, [], $request->batchSize());
        $run->reencrypted($rescan->summary(), $cleaned->cleaned(), $this->clock->now());
        $this->runs->save($run);

        return $this->results->reencrypted(
            status: RotateStatus::Reencrypted,
            runId: $run->id(),
            state: $run->state(),
            workers: $workers,
            probe: $probe,
            scan: $rescan,
            reencryption: $moved,
            rewrittenSystemPaths: array_map(static fn(SystemValueChange $change): string => $change->pathString(), $changes),
            cacheClean: $cleaned,
            keyAppended: true,
            sourceIndices: array_keys($sources),
            newIndex: $newIndex,
            ringFingerprint: $run->ringFingerprint(),
        );
    }

    /**
     * @return array<int, Key> key index => key, for the index active before the run and every usable index below it
     */
    private function sources(RotationRun $run, KeyRing $ring): array
    {
        $sources = [];
        foreach ($run->movedIndices() as $index) {
            $key = $ring->slot($index)?->key($this->keys);
            if ($key !== null) {
                $sources[$index] = $key;
            }
        }

        return $sources;
    }
}
