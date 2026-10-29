<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see SystemValueChange} values; implemented by the container build.
 */
#[CreatesInstancesOf(SystemValueChange::class)]
interface SystemValueChangeFactory
{
    /**
     * @param list<string> $path the keys below `system` leading to the value, outermost first
     *
     * @throws InvalidValue when the path is empty or holds an empty key
     */
    public function create(array $path, Ciphertext $expectedOld, Ciphertext $new): SystemValueChange;
}
