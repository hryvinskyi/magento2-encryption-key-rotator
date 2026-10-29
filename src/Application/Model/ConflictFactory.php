<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see Conflict} values; implemented by the container build.
 */
#[CreatesInstancesOf(Conflict::class)]
interface ConflictFactory
{
    public function create(ColumnRef $column, RowKey $rowKey, ConflictReason $reason): Conflict;
}
