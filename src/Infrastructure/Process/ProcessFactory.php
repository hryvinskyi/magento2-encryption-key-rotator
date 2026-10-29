<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;
use Symfony\Component\Process\Process;

/**
 * Creates the subprocesses the adapters run; implemented by the container build. A command line is an
 * executable and its arguments, never passed through a shell.
 */
#[CreatesInstancesOf(Process::class)]
interface ProcessFactory
{
    /**
     * A subprocess that inherits the tool's environment and reads nothing on its standard input.
     *
     * @param list<string> $command the executable and its arguments
     * @param string|null  $cwd     the working directory, or null for the tool's own
     * @param float|null   $timeout seconds the process may run, or null for no limit
     */
    public function create(array $command, ?string $cwd, ?float $timeout): Process;

    /**
     * A subprocess with a given environment that reads the given input on its standard input.
     *
     * @param list<string>               $command the executable and its arguments
     * @param string|null                $cwd     the working directory, or null for the tool's own
     * @param array<string, string>|null $env     the environment, or null to inherit the tool's
     * @param mixed                      $input   what the process reads on its standard input
     * @param float|null                 $timeout seconds the process may run, or null for no limit
     */
    public function createWithInput(array $command, ?string $cwd, ?array $env, mixed $input, ?float $timeout): Process;
}
