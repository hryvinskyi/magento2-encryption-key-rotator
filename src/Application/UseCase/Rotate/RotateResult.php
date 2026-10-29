<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * What a rotation call did, for the operator:
 * - how it ended ({@see RotateStatus}) and, once a run exists, its id and state;
 * - every refusal, and the processes that may hold an earlier key ring (blocking, or let run);
 * - the last web tier answer;
 * - the scan: the plan of a dry run, or the rescan after the values moved, with what remains;
 * - what the re-encryption wrote and left, the deployment configuration paths rewritten, and whether the
 *   configuration cache was cleaned;
 * - the old indices whose values move, the new index and the ring fingerprint the run recorded;
 * - whether the key ring now holds the new key: from then on bearer tokens signed with the previous key
 *   stop working, since the store signs and verifies them with the last key only.
 *
 * Created through {@see RotateResultFactory}.
 */
final class RotateResult
{
    /**
     * @param RotateStatus         $status               how the call ended
     * @param RunId|null           $runId                the run, once one exists
     * @param RunState|null        $state                where the run stands
     * @param list<Refusal>        $refusals             why the call stopped
     * @param list<RunningProcess> $workers              the processes that may hold an earlier key ring
     * @param ProbeOutcome|null    $probe                the last web tier answer
     * @param ScanReport|null      $scan                 the plan of a dry run, or the rescan after the move
     * @param ReencryptionOutcome|null $reencryption     what the database re-encryption did
     * @param list<string>         $rewrittenSystemPaths the deployment configuration paths rewritten
     * @param CacheCleanOutcome|null $cacheClean         the configuration cache clean
     * @param bool                 $keyAppended          whether the key ring holds the new key
     * @param list<int>            $sourceIndices        the old indices whose values move
     * @param int|null             $newIndex             the index of the new key
     * @param string|null          $ringFingerprint      the ring the run recorded, or the ring found by a dry run
     */
    public function __construct(
        private readonly RotateStatus $status,
        private readonly ?RunId $runId = null,
        private readonly ?RunState $state = null,
        private readonly array $refusals = [],
        private readonly array $workers = [],
        private readonly ?ProbeOutcome $probe = null,
        private readonly ?ScanReport $scan = null,
        private readonly ?ReencryptionOutcome $reencryption = null,
        private readonly array $rewrittenSystemPaths = [],
        private readonly ?CacheCleanOutcome $cacheClean = null,
        private readonly bool $keyAppended = false,
        private readonly array $sourceIndices = [],
        private readonly ?int $newIndex = null,
        private readonly ?string $ringFingerprint = null,
    ) {}

    public function status(): RotateStatus
    {
        return $this->status;
    }

    public function runId(): ?RunId
    {
        return $this->runId;
    }

    public function state(): ?RunState
    {
        return $this->state;
    }

    /**
     * @return list<Refusal>
     */
    public function refusals(): array
    {
        return $this->refusals;
    }

    /**
     * @return list<RunningProcess>
     */
    public function workers(): array
    {
        return $this->workers;
    }

    public function probe(): ?ProbeOutcome
    {
        return $this->probe;
    }

    public function scan(): ?ScanReport
    {
        return $this->scan;
    }

    public function reencryption(): ?ReencryptionOutcome
    {
        return $this->reencryption;
    }

    /**
     * @return list<string>
     */
    public function rewrittenSystemPaths(): array
    {
        return $this->rewrittenSystemPaths;
    }

    public function cacheClean(): ?CacheCleanOutcome
    {
        return $this->cacheClean;
    }

    /**
     * Whether bearer tokens signed with the previous key stopped working: true once the key ring holds
     * the new key.
     */
    public function bearerTokensInvalidated(): bool
    {
        return $this->keyAppended;
    }

    /**
     * @return list<int>
     */
    public function sourceIndices(): array
    {
        return $this->sourceIndices;
    }

    public function newIndex(): ?int
    {
        return $this->newIndex;
    }

    public function ringFingerprint(): ?string
    {
        return $this->ringFingerprint;
    }
}
