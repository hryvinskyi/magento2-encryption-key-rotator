<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see StoredValue} values; implemented by the container build.
 */
#[CreatesInstancesOf(StoredValue::class)]
interface StoredValueFactory
{
    public function create(RowKey $rowKey, string $raw): StoredValue;
}
