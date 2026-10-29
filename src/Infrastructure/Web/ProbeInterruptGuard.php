<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

/**
 * Deletes the probe file when the process is interrupted while the file is in place.
 *
 * With the pcntl extension, SIGINT, SIGTERM and SIGHUP are delivered asynchronously while the guarded
 * work runs. The first of them deletes the file, then hands the signal on: to the handler that was
 * installed before, when there was one, otherwise the process exits with 128 plus the signal number
 * (130 for SIGINT), as a shell reports a process the signal ended. A signal the process ignored before
 * (SIGHUP under `nohup`) stays ignored. When the work ends, the handlers and the asynchronous delivery
 * are put back as they were.
 *
 * Without pcntl the work simply runs; a file a killed process leaves is then removed by the sweep before
 * the next probe ({@see ProbeScriptWriter::sweep()}). SIGKILL can never be caught, so the sweep covers
 * it in every case.
 */
final class ProbeInterruptGuard
{
    private const EXIT_BY_SIGNAL = 128;

    public function __construct(
        private readonly ProbeScriptWriter $writer,
    ) {}

    /**
     * @template T
     *
     * @param string        $path the probe file the work puts in place
     * @param \Closure(): T $work
     *
     * @return T what the work returns
     */
    public function protect(string $path, \Closure $work): mixed
    {
        if (!function_exists('pcntl_signal') || !function_exists('pcntl_async_signals') || !function_exists('pcntl_signal_get_handler')) {
            return $work();
        }

        $wasAsync = pcntl_async_signals(true);
        $previous = [];
        foreach ([\SIGINT, \SIGTERM, \SIGHUP] as $signal) {
            $handler = pcntl_signal_get_handler($signal);
            if ($handler === \SIG_IGN) {
                continue;
            }
            $previous[$signal] = $handler;
            pcntl_signal($signal, function (int $received, mixed $info) use ($path, $handler): void {
                $this->writer->remove($path);
                if (is_callable($handler)) {
                    $this->handOn($handler, $received, $info);

                    return;
                }

                exit(self::EXIT_BY_SIGNAL + $received);
            });
        }

        try {
            return $work();
        } finally {
            foreach ($previous as $signal => $handler) {
                pcntl_signal($signal, $handler);
            }
            pcntl_async_signals($wasAsync);
        }
    }

    /**
     * Hands a signal on to the handler that was installed before the guard's.
     */
    private function handOn(callable $handler, int $signal, mixed $info): void
    {
        $handler($signal, $info);
    }
}
