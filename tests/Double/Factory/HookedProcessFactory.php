<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessFactory;
use Symfony\Component\Process\Process;

/**
 * Creates real subprocesses, and lets a test reach in before each subprocess that reads standard input
 * is created: the hook gets the call's number (from 1) and the input, may act on the world in between
 * (another writer replacing a file), and returns the input the subprocess reads.
 */
final class HookedProcessFactory implements ProcessFactory
{
    private int $calls = 0;

    /**
     * @param \Closure(int, mixed): mixed $beforeEach
     */
    public function __construct(
        private readonly \Closure $beforeEach,
    ) {}

    public function create(array $command, ?string $cwd, ?float $timeout): Process
    {
        return new Process($command, $cwd, null, null, $timeout);
    }

    public function createWithInput(array $command, ?string $cwd, ?array $env, mixed $input, ?float $timeout): Process
    {
        return new Process($command, $cwd, $env, ($this->beforeEach)(++$this->calls, $input), $timeout);
    }
}
