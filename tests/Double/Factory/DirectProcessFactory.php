<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessFactory;
use Symfony\Component\Process\Process;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectProcessFactory implements ProcessFactory
{
    public function create(array $command, ?string $cwd, ?float $timeout): Process
    {
        return new Process($command, $cwd, null, null, $timeout);
    }

    public function createWithInput(array $command, ?string $cwd, ?array $env, mixed $input, ?float $timeout): Process
    {
        return new Process($command, $cwd, $env, $input, $timeout);
    }
}
