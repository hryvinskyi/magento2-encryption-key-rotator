<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectPurgeResultFactory implements PurgeResultFactory
{
    public function stopped(
        PurgeStatus $status,
        ?RunId $runId,
        ?RunState $state,
        array $refusals,
        ?ScanReport $scan,
        array $purgedIndices,
        int $stillReadable,
        int $embedded,
        int $incompleteColumns,
        int $withoutRowKey,
    ): PurgeResult {
        return new PurgeResult(
            status: $status,
            runId: $runId,
            state: $state,
            refusals: $refusals,
            scan: $scan,
            purgedIndices: $purgedIndices,
            stillReadable: $stillReadable,
            embedded: $embedded,
            incompleteColumns: $incompleteColumns,
            withoutRowKey: $withoutRowKey,
        );
    }

    public function purged(
        PurgeStatus $status,
        RunId $runId,
        RunState $state,
        ScanReport $scan,
        array $purgedIndices,
        int $stillReadable,
        int $embedded,
        int $incompleteColumns,
        int $withoutRowKey,
        bool $acceptedLoss,
        int $journalEntriesDeleted,
        bool $runDirectoryRemoved,
    ): PurgeResult {
        return new PurgeResult(
            status: $status,
            runId: $runId,
            state: $state,
            scan: $scan,
            purgedIndices: $purgedIndices,
            stillReadable: $stillReadable,
            embedded: $embedded,
            incompleteColumns: $incompleteColumns,
            withoutRowKey: $withoutRowKey,
            acceptedLoss: $acceptedLoss,
            journalEntriesDeleted: $journalEntriesDeleted,
            runDirectoryRemoved: $runDirectoryRemoved,
        );
    }
}
