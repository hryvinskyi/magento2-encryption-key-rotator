<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * What a retirement call did, for the operator:
 * - how it ended ({@see RetireStatus}) and, once a run was found, its id and state;
 * - every refusal, and the processes that may hold an earlier key ring (blocking, or let run);
 * - the last web tier answer;
 * - the last scan: the one that refused the retirement, or the final one after the stragglers moved,
 *   which counts what is still left on the retired indices;
 * - the stragglers moved before the ring write and after it, the deployment configuration paths
 *   rewritten after it, and the last configuration cache clean;
 * - the indices retired and the ring fingerprint the run recorded.
 *
 * Created through {@see RetireResultFactory}.
 */
final class RetireResult
{
    /**
     * @param RetireStatus             $status                how the call ended
     * @param RunId|null               $runId                 the run, once one was found
     * @param RunState|null            $state                 where the run stands
     * @param list<Refusal>            $refusals              why the call stopped
     * @param list<RunningProcess>     $workers               the processes that may hold an earlier key ring
     * @param ProbeOutcome|null        $probe                 the last web tier answer
     * @param ScanReport|null          $scan                  the last scan
     * @param ReencryptionOutcome|null $stragglersBeforeWrite what moved onto the active key before the ring write
     * @param ReencryptionOutcome|null $stragglersAfterWrite  what moved onto the active key after it, with the kept keys
     * @param list<string>             $rewrittenSystemPaths  the deployment configuration paths rewritten after the ring write
     * @param CacheCleanOutcome|null   $cacheClean            the last configuration cache clean
     * @param list<int>                $retiredIndices        the indices whose keys are replaced by placeholders
     * @param string|null              $ringFingerprint       the ring the run recorded
     */
    public function __construct(
        private readonly RetireStatus $status,
        private readonly ?RunId $runId = null,
        private readonly ?RunState $state = null,
        private readonly array $refusals = [],
        private readonly array $workers = [],
        private readonly ?ProbeOutcome $probe = null,
        private readonly ?ScanReport $scan = null,
        private readonly ?ReencryptionOutcome $stragglersBeforeWrite = null,
        private readonly ?ReencryptionOutcome $stragglersAfterWrite = null,
        private readonly array $rewrittenSystemPaths = [],
        private readonly ?CacheCleanOutcome $cacheClean = null,
        private readonly array $retiredIndices = [],
        private readonly ?string $ringFingerprint = null,
    ) {}

    public function status(): RetireStatus
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

    public function stragglersBeforeWrite(): ?ReencryptionOutcome
    {
        return $this->stragglersBeforeWrite;
    }

    public function stragglersAfterWrite(): ?ReencryptionOutcome
    {
        return $this->stragglersAfterWrite;
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
     * @return list<int>
     */
    public function retiredIndices(): array
    {
        return $this->retiredIndices;
    }

    public function ringFingerprint(): ?string
    {
        return $this->ringFingerprint;
    }
}
