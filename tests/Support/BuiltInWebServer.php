<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Symfony\Component\Process\Process;

/**
 * PHP's built-in web server on a free loopback port, serving a document root and running any `.php`
 * file in it, the way a web server configured to execute arbitrary PHP files does. Stopped with
 * {@see stop()}.
 */
final class BuiltInWebServer
{
    private function __construct(
        private readonly Process $process,
        public readonly int $port,
    ) {}

    public static function start(string $documentRoot): self
    {
        $probe = stream_socket_server('tcp://127.0.0.1:0');
        if ($probe === false) {
            throw new \RuntimeException('No free loopback port.');
        }
        $name = (string) stream_socket_get_name($probe, false);
        fclose($probe);
        $port = (int) substr($name, strrpos($name, ':') + 1);

        $process = new Process([PHP_BINARY, '-S', '127.0.0.1:' . $port, '-t', $documentRoot], $documentRoot);
        $process->start();
        for ($attempt = 0; $attempt < 100; $attempt++) {
            $connection = @stream_socket_client('tcp://127.0.0.1:' . $port, $errno, $error, 0.1);
            if ($connection !== false) {
                fclose($connection);

                return new self($process, $port);
            }
            if (!$process->isRunning()) {
                break;
            }
            usleep(50_000);
        }
        $process->stop(1);
        throw new \RuntimeException('The built-in web server did not start: ' . $process->getErrorOutput());
    }

    public function baseUrl(): string
    {
        return 'http://127.0.0.1:' . $this->port;
    }

    public function stop(): void
    {
        $this->process->stop(2);
    }
}
