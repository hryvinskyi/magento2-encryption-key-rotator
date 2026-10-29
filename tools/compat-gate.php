<?php

declare(strict_types=1);

/*
 * Precondition of the compatibility suite: a Magento root to test against, and a PHP that root accepts.
 *
 * MAGENTO_ROOT names the root. MAGENTO_PHP (default `php`) is the executable the suite runs Magento's
 * own code with; it must satisfy the root's vendor/composer/platform_check.php. The gate fails with the
 * reason when either is wrong: the suite is never skipped.
 */

/**
 * @return never
 */
function refuse(string $message): void
{
    fwrite(STDERR, "test:compat cannot run: " . $message . "\n");
    exit(1);
}

$root = getenv('MAGENTO_ROOT');
if (!is_string($root) || $root === '') {
    refuse('MAGENTO_ROOT is not set. Point it at a Magento root with its dependencies installed, e.g. MAGENTO_ROOT=/path/to/magento composer test:compat');
}
if (!is_file($root . '/vendor/autoload.php')) {
    refuse(sprintf('MAGENTO_ROOT "%s" has no vendor/autoload.php; it is not an installed Magento root.', $root));
}
$platformCheck = $root . '/vendor/composer/platform_check.php';
if (!is_file($platformCheck)) {
    refuse(sprintf('"%s" does not exist, so the PHP it needs cannot be verified. Run composer install in MAGENTO_ROOT with the platform check enabled.', $platformCheck));
}

$php = getenv('MAGENTO_PHP');
$php = is_string($php) && $php !== '' ? $php : 'php';
$command = sprintf('%s -d display_errors=stderr %s 2>&1', escapeshellarg($php), escapeshellarg($platformCheck));
exec($command, $output, $exitCode);
if ($exitCode !== 0) {
    refuse(sprintf(
        "the PHP named by MAGENTO_PHP (\"%s\") does not satisfy %s (exit code %d):\n%s\nSet MAGENTO_PHP to a PHP that this Magento root supports.",
        $php,
        $platformCheck,
        $exitCode,
        implode("\n", $output),
    ));
}

fwrite(STDOUT, sprintf("Compatibility suite: Magento root %s, PHP %s\n", $root, $php));
