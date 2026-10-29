<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

use Symfony\Component\Process\Exception\ExceptionInterface as ProcessException;

/**
 * Reads the process list through `ps`.
 *
 * It asks first for `pid,ppid,etimes,args` across all processes. A minimal `ps` that knows no `etimes`
 * refuses that, and is asked for `pid,ppid,args`, which such a `ps` lists for every process: those entries
 * carry no elapsed time. When neither works (no `ps` on the host), the list is unavailable.
 */
final class PsProcessTable implements ProcessTable
{
    public const TIMEOUT_SECONDS = 5.0;

    private const WITH_ELAPSED = '/^\s*(\d+)\s+(\d+)\s+(\d+)\s+(.*)$/';
    private const WITHOUT_ELAPSED = '/^\s*(\d+)\s+(\d+)\s+(.*)$/';

    /**
     * @param string $ps the `ps` executable, looked up on the PATH unless it is a path
     */
    public function __construct(
        private readonly ProcessFactory $processes,
        private readonly string $ps = 'ps',
    ) {}

    public function processes(): ?array
    {
        $output = $this->run([$this->ps, '-eo', 'pid,ppid,etimes,args']);
        if ($output !== null) {
            return $this->parse($output, true);
        }
        $output = $this->run([$this->ps, '-o', 'pid,ppid,args']);
        if ($output !== null) {
            return $this->parse($output, false);
        }

        return null;
    }

    /**
     * @param list<string> $command
     *
     * @return string|null the standard output, or null when the command failed or could not run
     */
    private function run(array $command): ?string
    {
        $process = $this->processes->create($command, null, self::TIMEOUT_SECONDS);
        try {
            $process->run();
        } catch (ProcessException) {
            return null;
        }

        return $process->isSuccessful() ? $process->getOutput() : null;
    }

    /**
     * @return list<array{pid: int, ppid: int, elapsed: int|null, args: string}>
     */
    private function parse(string $output, bool $withElapsed): array
    {
        $lines = preg_split('/\R/', trim($output)) ?: [];
        array_shift($lines);

        $processes = [];
        foreach ($lines as $line) {
            $process = $withElapsed ? $this->withElapsed($line) : $this->withoutElapsed($line);
            if ($process !== null) {
                $processes[] = $process;
            }
        }

        return $processes;
    }

    /**
     * @return array{pid: int, ppid: int, elapsed: int, args: string}|null
     */
    private function withElapsed(string $line): ?array
    {
        if (preg_match(self::WITH_ELAPSED, $line, $match) !== 1) {
            return null;
        }

        return ['pid' => (int) $match[1], 'ppid' => (int) $match[2], 'elapsed' => (int) $match[3], 'args' => trim($match[4])];
    }

    /**
     * @return array{pid: int, ppid: int, elapsed: null, args: string}|null
     */
    private function withoutElapsed(string $line): ?array
    {
        if (preg_match(self::WITHOUT_ELAPSED, $line, $match) !== 1) {
            return null;
        }

        return ['pid' => (int) $match[1], 'ppid' => (int) $match[2], 'elapsed' => null, 'args' => trim($match[3])];
    }
}
