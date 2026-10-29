<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A row a compare-and-swap left alone, and why: its value changed since it was read, or it is gone.
 *
 * Created through {@see ConflictFactory}.
 */
final class Conflict
{
    public function __construct(
        private readonly ColumnRef $column,
        private readonly RowKey $rowKey,
        private readonly ConflictReason $reason,
    ) {}

    public function column(): ColumnRef
    {
        return $this->column;
    }

    public function rowKey(): RowKey
    {
        return $this->rowKey;
    }

    public function reason(): ConflictReason
    {
        return $this->reason;
    }
}
