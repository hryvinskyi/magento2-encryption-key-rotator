<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRetireResultFactory implements RetireResultFactory
{
    public function stopped(
        RetireStatus $status,
        ?RunId $runId,
        ?RunState $state,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        ?ScanReport $scan,
        ?string $ringFingerprint,
    ): RetireResult {
        return new RetireResult(
            status: $status,
            runId: $runId,
            state: $state,
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            scan: $scan,
            ringFingerprint: $ringFingerprint,
        );
    }

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
    ): RetireResult {
        return new RetireResult(
            status: $status,
            runId: $runId,
            state: $state,
            workers: $workers,
            probe: $probe,
            scan: $scan,
            stragglersBeforeWrite: $stragglersBeforeWrite,
            stragglersAfterWrite: $stragglersAfterWrite,
            rewrittenSystemPaths: $rewrittenSystemPaths,
            cacheClean: $cacheClean,
            retiredIndices: $retiredIndices,
            ringFingerprint: $ringFingerprint,
        );
    }
}
