<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates run ids; implemented by the container build.
 */
#[CreatesInstancesOf(RunId::class)]
interface RunIdFactory
{
    /**
     * @throws InvalidRunId when the value is not 32 lowercase hexadecimal characters
     */
    public function create(string $value): RunId;
}
