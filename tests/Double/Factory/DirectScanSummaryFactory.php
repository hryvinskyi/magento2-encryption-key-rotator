<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectScanSummaryFactory implements ScanSummaryFactory
{
    public function create(
        array $verifiedPerIndex,
        int $undecryptable,
        int $embedded,
        int $incompleteColumns,
        array $withoutRowKeyPerIndex,
    ): ScanSummary {
        return new ScanSummary($verifiedPerIndex, $undecryptable, $embedded, $incompleteColumns, $withoutRowKeyPerIndex);
    }
}
