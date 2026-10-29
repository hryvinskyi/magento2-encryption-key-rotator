<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRotateResultFactory implements RotateResultFactory
{
    public function dryRun(
        RotateStatus $status,
        ScanReport $scan,
        array $refusals,
        array $workers,
        array $sourceIndices,
        int $newIndex,
        string $ringFingerprint,
    ): RotateResult {
        return new RotateResult(
            status: $status,
            refusals: $refusals,
            workers: $workers,
            scan: $scan,
            sourceIndices: $sourceIndices,
            newIndex: $newIndex,
            ringFingerprint: $ringFingerprint,
        );
    }

    public function stopped(
        RotateStatus $status,
        ?RunId $runId,
        ?RunState $state,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        bool $keyAppended,
        ?string $ringFingerprint,
    ): RotateResult {
        return new RotateResult(
            status: $status,
            runId: $runId,
            state: $state,
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            keyAppended: $keyAppended,
            ringFingerprint: $ringFingerprint,
        );
    }

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
    ): RotateResult {
        return new RotateResult(
            status: $status,
            runId: $runId,
            state: $state,
            workers: $workers,
            probe: $probe,
            scan: $scan,
            reencryption: $reencryption,
            rewrittenSystemPaths: $rewrittenSystemPaths,
            cacheClean: $cacheClean,
            keyAppended: $keyAppended,
            sourceIndices: $sourceIndices,
            newIndex: $newIndex,
            ringFingerprint: $ringFingerprint,
        );
    }
}
