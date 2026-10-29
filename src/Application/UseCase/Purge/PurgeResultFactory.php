<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see PurgeResult} values; implemented by the container build. Each method names the fields one
 * way of ending fills.
 */
#[CreatesInstancesOf(PurgeResult::class)]
interface PurgeResultFactory
{
    /**
     * A call that deleted nothing: refused, or nothing to purge.
     *
     * @param list<Refusal> $refusals
     * @param list<int>     $purgedIndices
     */
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
    ): PurgeResult;

    /**
     * A call that purged the run.
     *
     * @param list<int> $purgedIndices
     */
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
    ): PurgeResult;
}
