<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A value read from a column: the row it belongs to and its bytes exactly as stored.
 *
 * Created through {@see StoredValueFactory}.
 */
final class StoredValue
{
    public function __construct(
        private readonly RowKey $rowKey,
        private readonly string $raw,
    ) {}

    public function rowKey(): RowKey
    {
        return $this->rowKey;
    }

    /**
     * The stored bytes, unchanged.
     */
    public function raw(): string
    {
        return $this->raw;
    }
}
