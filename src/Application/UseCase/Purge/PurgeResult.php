<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * What a purge call did, for the operator:
 * - how it ended ({@see PurgeStatus}), the run and its state (`purged` once the run is gone: its record
 *   was deleted with the run directory, so the state directory no longer knows the run);
 * - every refusal;
 * - the scan with the kept keys of the indices the purge makes unreadable for good, and what it found
 *   there: values that still decrypt only with a kept key, whole ciphertexts in columns without a row
 *   key (which the scan cannot verify, and which become unreadable with the keys), embedded values and
 *   cut-short columns, which may hold such values and cannot be ruled out;
 * - whether the operator accepted losing those values, how many journal entries were deleted, and
 *   whether the run directory, the kept keys with it, is gone.
 *
 * Created through {@see PurgeResultFactory}.
 */
final class PurgeResult
{
    /**
     * @param PurgeStatus     $status                how the call ended
     * @param RunId|null      $runId                 the run, once one was found
     * @param RunState|null   $state                 where the run stands
     * @param list<Refusal>   $refusals              why the call stopped
     * @param ScanReport|null $scan                  the scan of the purged indices with the kept keys
     * @param list<int>       $purgedIndices         the indices the purge makes unreadable for good
     * @param int             $stillReadable         values on those indices that still decrypt with a kept key
     * @param int             $embedded              values with a ciphertext embedded inside, which the scan cannot judge
     * @param int             $incompleteColumns     columns whose scan was cut short
     * @param int             $withoutRowKey         whole ciphertexts on those indices in columns without a row key
     * @param bool            $acceptedLoss          whether the operator accepted losing such values
     * @param int             $journalEntriesDeleted the journal entries deleted
     * @param bool            $runDirectoryRemoved   whether the run directory and its kept keys are gone
     */
    public function __construct(
        private readonly PurgeStatus $status,
        private readonly ?RunId $runId = null,
        private readonly ?RunState $state = null,
        private readonly array $refusals = [],
        private readonly ?ScanReport $scan = null,
        private readonly array $purgedIndices = [],
        private readonly int $stillReadable = 0,
        private readonly int $embedded = 0,
        private readonly int $incompleteColumns = 0,
        private readonly int $withoutRowKey = 0,
        private readonly bool $acceptedLoss = false,
        private readonly int $journalEntriesDeleted = 0,
        private readonly bool $runDirectoryRemoved = false,
    ) {}

    public function status(): PurgeStatus
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

    public function scan(): ?ScanReport
    {
        return $this->scan;
    }

    /**
     * @return list<int>
     */
    public function purgedIndices(): array
    {
        return $this->purgedIndices;
    }

    public function stillReadable(): int
    {
        return $this->stillReadable;
    }

    public function embedded(): int
    {
        return $this->embedded;
    }

    public function incompleteColumns(): int
    {
        return $this->incompleteColumns;
    }

    public function withoutRowKey(): int
    {
        return $this->withoutRowKey;
    }

    public function acceptedLoss(): bool
    {
        return $this->acceptedLoss;
    }

    public function journalEntriesDeleted(): int
    {
        return $this->journalEntriesDeleted;
    }

    public function runDirectoryRemoved(): bool
    {
        return $this->runDirectoryRemoved;
    }
}
