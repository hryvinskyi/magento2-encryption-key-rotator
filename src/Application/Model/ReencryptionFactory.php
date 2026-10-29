<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see Reencryption} values; implemented by the container build.
 */
#[CreatesInstancesOf(Reencryption::class)]
interface ReencryptionFactory
{
    public function create(ColumnRef $column, RowKey $rowKey, string $oldRaw, Ciphertext $new): Reencryption;
}
