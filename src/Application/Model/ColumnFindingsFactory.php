<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ColumnFindings} values; implemented by the container build.
 */
#[CreatesInstancesOf(ColumnFindings::class)]
interface ColumnFindingsFactory
{
    /**
     * @param array<int, array<string, int>> $perIndex key index => verdict value => count
     *
     * @throws InvalidValue when a key index, a verdict or a count is out of range
     */
    public function create(ColumnCandidate $candidate, array $perIndex): ColumnFindings;
}
