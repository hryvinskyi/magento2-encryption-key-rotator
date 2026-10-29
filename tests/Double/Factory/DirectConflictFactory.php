<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectConflictFactory implements ConflictFactory
{
    public function create(ColumnRef $column, RowKey $rowKey, ConflictReason $reason): Conflict
    {
        return new Conflict($column, $rowKey, $reason);
    }
}
