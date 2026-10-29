<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcessFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRunningProcessFactory implements RunningProcessFactory
{
    public function create(string $description, ?\DateTimeImmutable $startedAt): RunningProcess
    {
        return new RunningProcess($description, $startedAt);
    }
}
