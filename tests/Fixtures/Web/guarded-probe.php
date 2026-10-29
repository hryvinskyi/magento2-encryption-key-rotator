<?php

/*
 * Puts a probe file in place under the interrupt guard and waits to be interrupted, for the test of
 * what a signal does to a probe in flight. Arguments: the probe file's directory, then `ignore-hup`
 * to start with SIGHUP ignored, as `nohup` starts a process. It prints the probe file's path once the
 * file is in place, and "survived" if the wait ends without the process being stopped.
 */

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeInterruptGuard;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web\ProbeScriptWriter;

require dirname(__DIR__, 3) . '/vendor/autoload.php';

$arguments = $_SERVER['argv'] ?? null;
$directory = is_array($arguments) && isset($arguments[1]) && is_string($arguments[1]) ? $arguments[1] : null;
if ($directory === null) {
    fwrite(STDERR, "Give the probe file's directory.\n");
    exit(2);
}
if (($arguments[2] ?? null) === 'ignore-hup') {
    pcntl_signal(SIGHUP, SIG_IGN);
}

$writer = new ProbeScriptWriter();
$path = $directory . '/' . $writer->newFileName();
(new ProbeInterruptGuard($writer))->protect($path, static function () use ($writer, $path): void {
    $writer->write($path, '<?php http_response_code(404);');
    echo $path, "\n";
    for ($waited = 0; $waited < 40; $waited++) {
        usleep(50_000);
    }
});
echo "survived\n";
