<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\StoredValueFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectStoredValueFactory implements StoredValueFactory
{
    public function create(RowKey $rowKey, string $raw): StoredValue
    {
        return new StoredValue($rowKey, $raw);
    }
}
