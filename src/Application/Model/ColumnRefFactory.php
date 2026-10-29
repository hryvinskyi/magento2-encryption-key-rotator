<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ColumnRef} values; implemented by the container build.
 */
#[CreatesInstancesOf(ColumnRef::class)]
interface ColumnRefFactory
{
    /**
     * @param string $table  the table name without the prefix
     *
     * @throws InvalidValue when a name cannot be a table or column name
     */
    public function create(string $table, string $column): ColumnRef;
}
