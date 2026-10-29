<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidateFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectColumnCandidateFactory implements ColumnCandidateFactory
{
    public function create(
        ColumnRef $column,
        array $rowKeyColumns,
        array $autoUpdatedColumns,
        array $shapeCounts,
        int $embeddedCount,
        bool $scanIncomplete,
    ): ColumnCandidate {
        return new ColumnCandidate($column, $rowKeyColumns, $autoUpdatedColumns, $shapeCounts, $embeddedCount, $scanIncomplete);
    }
}
