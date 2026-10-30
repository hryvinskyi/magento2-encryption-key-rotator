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
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RotateResult} values; implemented by the container build. Each method names the fields
 * one way of ending fills.
 */
#[CreatesInstancesOf(RotateResult::class)]
interface RotateResultFactory
{
    /**
     * The plan of a dry run.
     *
     * @param list<Refusal>        $refusals      what would refuse the rotation now
     * @param list<RunningProcess> $workers
     * @param ProbeOutcome|null    $probe         the web tier's answer, when a probe transport was chosen
     * @param list<int>            $sourceIndices
     */
    public function dryRun(
        RotateStatus $status,
        ScanReport $scan,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        array $sourceIndices,
        int $newIndex,
        string $ringFingerprint,
    ): RotateResult;

    /**
     * A call that stopped before the values moved: refused, or waiting for the web tier.
     *
     * @param list<Refusal>        $refusals
     * @param list<RunningProcess> $workers
     */
    public function stopped(
        RotateStatus $status,
        ?RunId $runId,
        ?RunState $state,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        bool $keyAppended,
        ?string $ringFingerprint,
    ): RotateResult;

    /**
     * A call that moved the values onto the new key.
     *
     * @param list<RunningProcess> $workers
     * @param list<string>         $rewrittenSystemPaths
     * @param list<int>            $sourceIndices
     */
    public function reencrypted(
        RotateStatus $status,
        RunId $runId,
        RunState $state,
        array $workers,
        ?ProbeOutcome $probe,
        ScanReport $scan,
        ReencryptionOutcome $reencryption,
        array $rewrittenSystemPaths,
        CacheCleanOutcome $cacheClean,
        bool $keyAppended,
        array $sourceIndices,
        int $newIndex,
        string $ringFingerprint,
    ): RotateResult;
}
