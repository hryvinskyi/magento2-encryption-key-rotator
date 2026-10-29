<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ReencryptionFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectReencryptionFactory implements ReencryptionFactory
{
    public function create(ColumnRef $column, RowKey $rowKey, string $oldRaw, Ciphertext $new): Reencryption
    {
        return new Reencryption($column, $rowKey, $oldRaw, $new);
    }
}
