<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindingsFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectColumnFindingsFactory implements ColumnFindingsFactory
{
    public function create(ColumnCandidate $candidate, array $perIndex): ColumnFindings
    {
        return new ColumnFindings($candidate, $perIndex);
    }
}
