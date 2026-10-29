<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see WriteResult} values; implemented by the container build.
 */
#[CreatesInstancesOf(WriteResult::class)]
interface WriteResultFactory
{
    /**
     * @param list<Conflict> $conflicts
     *
     * @throws InvalidValue when the applied count is negative
     */
    public function create(int $applied, array $conflicts): WriteResult;
}
