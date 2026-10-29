<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * One value to rewrite: in that row of that column, replace exactly the old bytes with the new
 * ciphertext. The write is a compare-and-swap on the old bytes: a value changed since it was read is
 * left alone.
 *
 * Created through {@see ReencryptionFactory}.
 */
final class Reencryption
{
    /**
     * @param ColumnRef  $column the column
     * @param RowKey     $rowKey the row
     * @param string     $oldRaw the bytes the row must still hold for the write to happen
     * @param Ciphertext $new    the value to write, already verified to decrypt to the same plaintext
     */
    public function __construct(
        private readonly ColumnRef $column,
        private readonly RowKey $rowKey,
        private readonly string $oldRaw,
        private readonly Ciphertext $new,
    ) {}

    public function column(): ColumnRef
    {
        return $this->column;
    }

    public function rowKey(): RowKey
    {
        return $this->rowKey;
    }

    public function oldRaw(): string
    {
        return $this->oldRaw;
    }

    public function new(): Ciphertext
    {
        return $this->new;
    }
}
