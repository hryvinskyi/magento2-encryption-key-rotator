<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResult;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\WriteResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Writes a batch of re-encryptions in one transaction: a compare-and-swap per row on its exact old
 * bytes, then the journal rows of the writes that happened, then the commit. A row whose value changed
 * or is gone is a conflict and gets no journal row, so the journal only ever holds writes that were
 * made. Any failure rolls the whole batch back, values and journal alike.
 */
final class TransactionalReencryptionWriter implements ReencryptionWriter
{
    public function __construct(
        private readonly TransactionRunner $transactions,
        private readonly CompareAndSwap $compareAndSwap,
        private readonly JournalRows $journal,
        private readonly WriteResultFactory $results,
    ) {}

    public function apply(RunId $runId, Direction $direction, array $reencryptions): WriteResult
    {
        if ($reencryptions === []) {
            return $this->results->create(0, []);
        }

        return $this->transactions->run(function () use ($runId, $direction, $reencryptions): WriteResult {
            $applied = [];
            $conflicts = [];
            foreach ($reencryptions as $reencryption) {
                $conflict = $this->compareAndSwap->swap(
                    $reencryption->column(),
                    $reencryption->rowKey(),
                    $reencryption->oldRaw(),
                    $reencryption->new()->toString(),
                );
                if ($conflict !== null) {
                    $conflicts[] = $conflict;

                    continue;
                }
                $applied[] = $reencryption;
            }
            $this->journal->record($runId, $direction, $applied);

            return $this->results->create(count($applied), $conflicts);
        });
    }
}
