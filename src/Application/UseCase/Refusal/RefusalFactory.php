<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see Refusal} values; implemented by the container build.
 */
#[CreatesInstancesOf(Refusal::class)]
interface RefusalFactory
{
    public function create(RefusalReason $reason, string $message): Refusal;
}
