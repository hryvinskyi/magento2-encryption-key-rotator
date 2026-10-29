<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see RunningProcess} values; implemented by the container build.
 */
#[CreatesInstancesOf(RunningProcess::class)]
interface RunningProcessFactory
{
    public function create(string $description, ?\DateTimeImmutable $startedAt): RunningProcess;
}
