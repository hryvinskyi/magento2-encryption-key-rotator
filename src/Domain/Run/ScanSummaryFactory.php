<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates scan summaries; implemented by the container build.
 */
#[CreatesInstancesOf(ScanSummary::class)]
interface ScanSummaryFactory
{
    /**
     * @param array<int, int> $verifiedPerIndex      key index => values that decrypt under that slot
     * @param array<int, int> $withoutRowKeyPerIndex key index => whole ciphertexts under it in columns whose table has no row key
     *
     * @throws InvalidScanSummary when a count is negative or a key index is out of range
     */
    public function create(array $verifiedPerIndex, int $undecryptable, int $embedded, int $incompleteColumns, array $withoutRowKeyPerIndex): ScanSummary;
}
