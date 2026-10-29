<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Symfony\Component\Process\Process;

/**
 * A PHP-FPM master started for one test: a pool listening on a unix socket in a scratch directory,
 * opcache on with `validate_timestamps=0` (a file is compiled once and its copy kept, as on a production
 * pool), and no protection window for freshly written files. Stopped with {@see stop()}.
 */
final class FastCgiServer
{
    /**
     * The signal PHP-FPM reloads on (Linux numbering; the pcntl extension that names it is not needed).
     */
    private const SIGUSR2 = 12;

    private function __construct(
        private readonly Process $process,
        public readonly string $directory,
        public readonly string $socket,
    ) {}

    /**
     * @param list<string> $poolLines extra lines for the pool section
     */
    public static function start(array $poolLines = []): self
    {
        $directory = TemporaryDirectory::create('key-rotator-fpm');
        $socket = $directory . '/fpm.sock';
        $config = $directory . '/php-fpm.conf';
        file_put_contents($config, implode("\n", [
            '[global]',
            'error_log = ' . $directory . '/fpm.log',
            'daemonize = no',
            '[probe]',
            'listen = ' . $socket,
            'listen.mode = 0666',
            'pm = static',
            'pm.max_children = 2',
            'clear_env = no',
            ...$poolLines,
        ]) . "\n");

        $command = [
            'php-fpm', '-F', '-y', $config,
            '-d', 'opcache.enable=1',
            '-d', 'opcache.validate_timestamps=0',
            '-d', 'opcache.file_update_protection=0',
        ];
        if (function_exists('posix_geteuid') && posix_geteuid() === 0) {
            $command[] = '-R';
        }
        $process = new Process($command, $directory);
        $process->start();

        $server = new self($process, $directory, $socket);
        $server->waitFor($socket);

        return $server;
    }

    public function address(): string
    {
        return 'unix://' . $this->socket;
    }

    /**
     * Reloads the pool gracefully, as an operator does after a deploy: the new workers start with an
     * empty opcode cache and read every file afresh.
     */
    public function reload(): void
    {
        $this->process->signal(self::SIGUSR2);
        usleep(500_000);
        $this->waitFor($this->socket);
    }

    public function stop(): void
    {
        $this->process->stop(5);
        // PHP-FPM removes its socket when it stops; one left by a killed master is removed here.
        @unlink($this->socket);
        TemporaryDirectory::remove($this->directory);
    }

    private function waitFor(string $socket): void
    {
        for ($attempt = 0; $attempt < 100; $attempt++) {
            if (file_exists($socket)) {
                return;
            }
            if (!$this->process->isRunning()) {
                break;
            }
            usleep(50_000);
        }
        $log = @file_get_contents($this->directory . '/fpm.log');
        $this->process->stop(1);
        throw new \RuntimeException(sprintf(
            "PHP-FPM did not start: %s\n%s\n%s",
            $this->process->getErrorOutput(),
            $this->process->getOutput(),
            $log === false ? '' : $log,
        ));
    }
}
