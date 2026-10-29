<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Psr\Clock\ClockInterface;

/**
 * Finds the store's commands running on this host: every process that runs `bin/magento`, whatever the
 * command (cron runs and queue consumers, but also imports and indexers, which hold the key ring as
 * long). The tool's own process and its children are left out.
 *
 * A command line naming `bin/magento` by an absolute path belongs to the store whose root that path
 * starts with, so another store's commands on the same host are left out. A relative `bin/magento`
 * names no root and is counted.
 *
 * The start time is the clock's now minus the elapsed seconds the process list reports; without them it
 * is unknown. When the process list cannot be read at all, the result is one entry with an unknown start
 * time, so the caller can tell "nothing runs" from "nobody knows".
 */
final class ProcessWorkerActivity implements WorkerActivity
{
    public const UNAVAILABLE = 'process list unavailable: no ps on this host, so running store commands cannot be seen';

    private const MAGENTO_CLI = '~(?:^|\s)(\S*bin/magento)(?=\s|$)~';
    private const DESCRIPTION_LENGTH = 200;

    public function __construct(
        private readonly ProcessTable $table,
        private readonly MagentoRootProvider $roots,
        private readonly ClockInterface $clock,
        private readonly RunningProcessFactory $runningProcesses,
        private readonly SecretRedactor $redactor,
    ) {}

    public function running(): array
    {
        $processes = $this->table->processes();
        if ($processes === null) {
            return [$this->runningProcesses->create(self::UNAVAILABLE, null)];
        }

        $parents = [];
        foreach ($processes as $process) {
            $parents[$process['pid']] = $process['ppid'];
        }
        $roots = $this->rootPaths();
        $now = $this->clock->now();
        $own = getmypid();

        $running = [];
        foreach ($processes as $process) {
            if ($own !== false && $this->descendsFrom($process['pid'], $own, $parents)) {
                continue;
            }
            if (!$this->runsStoreCommand($process['args'], $roots)) {
                continue;
            }
            $running[] = $this->describe($process, $now);
        }

        return $running;
    }

    /**
     * @param array{pid: int, ppid: int, elapsed: int|null, args: string} $process
     */
    private function describe(array $process, \DateTimeImmutable $now): RunningProcess
    {
        $args = $this->redactedArguments($process['args']);
        if (strlen($args) > self::DESCRIPTION_LENGTH) {
            $args = substr($args, 0, self::DESCRIPTION_LENGTH) . '…';
        }
        $startedAt = $process['elapsed'] === null
            ? null
            : $now->setTimestamp($now->getTimestamp() - $process['elapsed']);

        return $this->runningProcesses->create(
            sprintf('pid %d: %s', $process['pid'], $args),
            $startedAt,
        );
    }

    /**
     * The command line with everything after `bin/magento` passed through the secret redactor: the
     * command's arguments may carry a key or a password, while the path of the executable is what the
     * operator needs to recognise the process, and a long path would read as a secret.
     */
    private function redactedArguments(string $args): string
    {
        if (preg_match(self::MAGENTO_CLI, $args, $match, PREG_OFFSET_CAPTURE) !== 1) {
            return $this->redactor->redact($args);
        }
        $end = $match[1][1] + strlen($match[1][0]);

        return substr($args, 0, $end) . $this->redactor->redact(substr($args, $end));
    }

    /**
     * Whether the process is that one or one of its descendants.
     *
     * @param array<int, int> $parents pid => parent pid
     */
    private function descendsFrom(int $pid, int $ancestor, array $parents): bool
    {
        $seen = [];
        while ($pid > 0 && !isset($seen[$pid])) {
            if ($pid === $ancestor) {
                return true;
            }
            $seen[$pid] = true;
            $pid = $parents[$pid] ?? 0;
        }

        return false;
    }

    /**
     * @param list<string> $roots
     */
    private function runsStoreCommand(string $args, array $roots): bool
    {
        if (preg_match_all(self::MAGENTO_CLI, $args, $matches) < 1) {
            return false;
        }
        foreach ($matches[1] as $cli) {
            if (!str_starts_with($cli, '/')) {
                return true;
            }
            if (in_array(dirname($cli, 2), $roots, true)) {
                return true;
            }
        }

        return false;
    }

    /**
     * The store's root as given and, when it runs through a symbolic link, as resolved.
     *
     * @return list<string>
     */
    private function rootPaths(): array
    {
        $path = $this->roots->root()->path();
        $resolved = realpath($path);

        return $resolved === false || $resolved === $path ? [$path] : [$path, $resolved];
    }
}
