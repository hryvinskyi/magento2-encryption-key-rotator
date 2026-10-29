<?php

declare(strict_types=1);

/*
 * Smoke test of the packed phar on the PHP that runs this script: `about` must pass its requirement
 * check, and `scan --format=json` must read a seeded store (the end-to-end tests' store: a scratch
 * Magento root and a database of its own on the server DB_SERVICE names) and exit 0 with the counts the
 * seed holds. Run inside the PHP containers by `composer build`; the store is removed afterwards.
 */

use Hryvinskyi\EncryptionKeyRotator\Tests\Support\EndToEndStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\Nested;
use Symfony\Component\Process\Process;

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

/**
 * @param list<string> $arguments
 */
function phar(string $root, array $arguments): Process
{
    $process = new Process([PHP_BINARY, $root . '/build/key-rotator.phar', ...$arguments], null, null, null, 120);
    $process->run();

    return $process;
}

/**
 * @return never
 */
function failSmoke(string $message, Process $process): void
{
    fwrite(STDERR, sprintf("%s\n[exit %s]\n%s\n%s\n", $message, var_export($process->getExitCode(), true), $process->getOutput(), $process->getErrorOutput()));
    exit(1);
}

if (!is_file($root . '/build/key-rotator.phar')) {
    fwrite(STDERR, "build/key-rotator.phar does not exist; run composer build:phar first.\n");
    exit(1);
}

$about = phar($root, ['about']);
if (!$about->isSuccessful()) {
    failSmoke('about failed', $about);
}

$store = EndToEndStore::create();
try {
    $scan = phar($root, ['scan', '--magento-root=' . $store->root, '--format=json']);
    if ($scan->getExitCode() !== 0) {
        failSmoke('scan failed', $scan);
    }
    $report = Nested::json($scan->getOutput());
    $totals = array_column(Nested::array($report, 'totals'), null, 'index');
    $expected = count($store->seededValues()) + 1;
    if (Nested::value($totals, 1, 'verified') !== $expected) {
        failSmoke(sprintf('scan counted other values under key index 1 than the %d seeded', $expected), $scan);
    }
    fwrite(STDOUT, sprintf(
        "PHP %s, %s: about ok; scan exit 0, %d column(s), %d value(s) verified under key index 1.\n",
        PHP_VERSION,
        (string) getenv('DB_SERVICE'),
        count(Nested::array($report, 'columns')),
        $expected,
    ));
} finally {
    $store->remove();
}
