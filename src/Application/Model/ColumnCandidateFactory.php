<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ColumnCandidate} values; implemented by the container build.
 */
#[CreatesInstancesOf(ColumnCandidate::class)]
interface ColumnCandidateFactory
{
    /**
     * @param list<string>    $rowKeyColumns
     * @param list<string>    $autoUpdatedColumns
     * @param array<int, int> $shapeCounts key index => values with the shape of a ciphertext under it
     *
     * @throws InvalidValue when a count or index is out of range
     */
    public function create(
        ColumnRef $column,
        array $rowKeyColumns,
        array $autoUpdatedColumns,
        array $shapeCounts,
        int $embeddedCount,
        bool $scanIncomplete,
    ): ColumnCandidate;
}
