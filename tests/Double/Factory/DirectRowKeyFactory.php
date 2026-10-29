<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKeyFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRowKeyFactory implements RowKeyFactory
{
    public function create(array $values): RowKey
    {
        return new RowKey($values);
    }
}
