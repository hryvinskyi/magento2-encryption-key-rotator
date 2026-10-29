<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RowKey} values; implemented by the container build.
 */
#[CreatesInstancesOf(RowKey::class)]
interface RowKeyFactory
{
    /**
     * @param array<array-key, int|float|string|bool> $values key column => value, in key order
     *
     * @throws InvalidValue when no column is given or a value cannot be journaled
     */
    public function create(array $values): RowKey;
}
