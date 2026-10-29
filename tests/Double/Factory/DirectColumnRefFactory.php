<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRefFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectColumnRefFactory implements ColumnRefFactory
{
    public function create(string $table, string $column): ColumnRef
    {
        return new ColumnRef($table, $column);
    }
}
