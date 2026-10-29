<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * What a rollback call did, for the operator:
 * - how it ended ({@see RollBackStatus}), the run, its state and the state the rollback started from;
 * - every refusal, and the processes that may hold an earlier key ring (blocking, or let run);
 * - the last web tier answer;
 * - what undoing the journal did, what moved off the new key afterwards (values the store wrote under it,
 *   then the stragglers found after the slot removal), the deployment configuration paths rewritten, the
 *   last configuration cache clean, and the final scan;
 * - the ring fingerprint the run recorded;
 * - the bearer token note, once the new key was in the ring: tokens signed with it stop working now
 *   that it is gone, since the store signs and verifies them with the last key only.
 *
 * Created through {@see RollBackResultFactory}.
 */
final class RollBackResult
{
    /**
     * @param RollBackStatus           $status               how the call ended
     * @param RunId|null               $runId                the run, once one was found
     * @param RunState|null            $state                where the run stands
     * @param RunState|null            $rolledBackFrom       the state the rollback started from
     * @param list<Refusal>            $refusals             why the call stopped
     * @param list<RunningProcess>     $workers              the processes that may hold an earlier key ring
     * @param ProbeOutcome|null        $probe                the last web tier answer
     * @param JournalReversalOutcome|null $journal           what undoing the journal did
     * @param ReencryptionOutcome|null $storeWritten         the values the store wrote under the new key, moved back
     * @param ReencryptionOutcome|null $stragglers           the values found under the new key after its slot was removed, moved back
     * @param list<string>             $rewrittenSystemPaths the deployment configuration paths rewritten
     * @param CacheCleanOutcome|null   $cacheClean           the last configuration cache clean
     * @param ScanReport|null          $scan                 the final scan, with the kept new key
     * @param string|null              $ringFingerprint      the ring the run recorded
     * @param string|null              $bearerTokenNote      the note on bearer tokens, once the new key was in the ring
     */
    public function __construct(
        private readonly RollBackStatus $status,
        private readonly ?RunId $runId = null,
        private readonly ?RunState $state = null,
        private readonly ?RunState $rolledBackFrom = null,
        private readonly array $refusals = [],
        private readonly array $workers = [],
        private readonly ?ProbeOutcome $probe = null,
        private readonly ?JournalReversalOutcome $journal = null,
        private readonly ?ReencryptionOutcome $storeWritten = null,
        private readonly ?ReencryptionOutcome $stragglers = null,
        private readonly array $rewrittenSystemPaths = [],
        private readonly ?CacheCleanOutcome $cacheClean = null,
        private readonly ?ScanReport $scan = null,
        private readonly ?string $ringFingerprint = null,
        private readonly ?string $bearerTokenNote = null,
    ) {}

    public function status(): RollBackStatus
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

    public function rolledBackFrom(): ?RunState
    {
        return $this->rolledBackFrom;
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

    public function journal(): ?JournalReversalOutcome
    {
        return $this->journal;
    }

    public function storeWritten(): ?ReencryptionOutcome
    {
        return $this->storeWritten;
    }

    public function stragglers(): ?ReencryptionOutcome
    {
        return $this->stragglers;
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

    public function scan(): ?ScanReport
    {
        return $this->scan;
    }

    public function ringFingerprint(): ?string
    {
        return $this->ringFingerprint;
    }

    public function bearerTokenNote(): ?string
    {
        return $this->bearerTokenNote;
    }
}
