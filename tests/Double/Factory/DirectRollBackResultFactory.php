<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\JournalReversalOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRollBackResultFactory implements RollBackResultFactory
{
    public function stopped(
        RollBackStatus $status,
        ?RunId $runId,
        ?RunState $state,
        ?RunState $rolledBackFrom,
        array $refusals,
        array $workers,
        ?ProbeOutcome $probe,
        ?string $ringFingerprint,
    ): RollBackResult {
        return new RollBackResult(
            status: $status,
            runId: $runId,
            state: $state,
            rolledBackFrom: $rolledBackFrom,
            refusals: $refusals,
            workers: $workers,
            probe: $probe,
            ringFingerprint: $ringFingerprint,
        );
    }

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
    ): RollBackResult {
        return new RollBackResult(
            status: $status,
            runId: $runId,
            state: $state,
            rolledBackFrom: $rolledBackFrom,
            workers: $workers,
            probe: $probe,
            journal: $journal,
            storeWritten: $storeWritten,
            stragglers: $stragglers,
            rewrittenSystemPaths: $rewrittenSystemPaths,
            cacheClean: $cacheClean,
            scan: $scan,
            ringFingerprint: $ringFingerprint,
            bearerTokenNote: $bearerTokenNote,
        );
    }
}
