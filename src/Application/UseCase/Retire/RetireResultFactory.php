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
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RetireResult} values; implemented by the container build. Each method names the fields
 * one way of ending fills.
 */
#[CreatesInstancesOf(RetireResult::class)]
interface RetireResultFactory
{
    /**
     * A call that stopped before the run was retired: refused, or waiting for the web tier.
     *
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    public function stopped(
        RetireStatus $status,
        ?RunId $runId,
        ?RunState $state,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        ?ScanReport $scan,
        ?string $ringFingerprint,
    ): RetireResult;

    /**
     * A call that retired the old keys.
     *
     * @param list<RunningProcess> $workers
     * @param list<string>         $rewrittenSystemPaths
     * @param list<int>            $retiredIndices
     */
    public function retired(
        RetireStatus $status,
        RunId $runId,
        RunState $state,
        array $workers,
        ?ProbeOutcome $probe,
        ScanReport $scan,
        ?ReencryptionOutcome $stragglersBeforeWrite,
        ReencryptionOutcome $stragglersAfterWrite,
        array $rewrittenSystemPaths,
        CacheCleanOutcome $cacheClean,
        array $retiredIndices,
        string $ringFingerprint,
    ): RetireResult;
}
