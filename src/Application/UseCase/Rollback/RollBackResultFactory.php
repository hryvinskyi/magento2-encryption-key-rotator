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
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RollBackResult} values; implemented by the container build. Each method names the fields
 * one way of ending fills.
 */
#[CreatesInstancesOf(RollBackResult::class)]
interface RollBackResultFactory
{
    /**
     * A call that did not finish the rollback: refused, waiting for the web tier, or nothing left to do.
     *
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    public function stopped(
        RollBackStatus $status,
        ?RunId $runId,
        ?RunState $state,
        ?RunState $rolledBackFrom,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        ?string $ringFingerprint,
    ): RollBackResult;

    /**
     * A call that finished the rollback.
     *
     * @param list<RunningProcess> $workers
     * @param list<string>         $rewrittenSystemPaths
     */
    public function rolledBack(
        RollBackStatus $status,
        RunId $runId,
        RunState $state,
        ?RunState $rolledBackFrom,
        array $workers,
        ?ProbeOutcome $probe,
        ?JournalReversalOutcome $journal,
        ?ReencryptionOutcome $storeWritten,
        ?ReencryptionOutcome $stragglers,
        array $rewrittenSystemPaths,
        CacheCleanOutcome $cacheClean,
        ScanReport $scan,
        string $ringFingerprint,
        ?string $bearerTokenNote,
    ): RollBackResult;
}
