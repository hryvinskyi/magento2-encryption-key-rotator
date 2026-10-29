<?php

declare(strict_types=1);

/*
 * Builds build/key-rotator.phar.
 *
 * 1. Compiles the service container, with its generated factories, into build/out/ (emptied first, so
 *    no factory of an earlier build is packed).
 * 2. Packs bin/, src/, build/out/ and the production dependencies with Box. Box is a pinned release,
 *    downloaded once into build/tools/ and checked against its SHA-256 before every run. Box needs
 *    PHP 8.2 or later, so it runs on the PHP that runs this script; the phar it produces runs on 8.1.
 */

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;

const BOX_VERSION = '4.7.0';
const BOX_SHA256 = '3d390eeaec33288098fe83f8a54c60cc575cb6be295f38ff4482b4b4f26f8d52';

$root = dirname(__DIR__);
require $root . '/vendor/autoload.php';

/**
 * @return never
 */
function fail(string $message): void
{
    fwrite(STDERR, $message . "\n");
    exit(1);
}

function removeTree(string $path): void
{
    if (!is_dir($path) || is_link($path)) {
        if (file_exists($path) || is_link($path)) {
            unlink($path);
        }

        return;
    }
    $entries = scandir($path);
    if ($entries === false) {
        fail(sprintf('Cannot read "%s".', $path));
    }
    foreach ($entries as $entry) {
        if ($entry !== '.' && $entry !== '..') {
            removeTree($path . '/' . $entry);
        }
    }
    rmdir($path);
}

function box(string $root): string
{
    $box = sprintf('%s/build/tools/box-%s.phar', $root, BOX_VERSION);
    if (!is_file($box)) {
        if (!is_dir(dirname($box)) && !mkdir(dirname($box), 0755, true)) {
            fail('Cannot create build/tools/.');
        }
        $url = sprintf('https://github.com/box-project/box/releases/download/%s/box.phar', BOX_VERSION);
        fwrite(STDOUT, sprintf("Downloading Box %s\n", BOX_VERSION));
        $content = file_get_contents($url);
        if ($content === false) {
            fail(sprintf('Cannot download %s.', $url));
        }
        if (hash('sha256', $content) !== BOX_SHA256) {
            fail(sprintf('The download of %s does not match the pinned SHA-256; it was not saved.', $url));
        }
        file_put_contents($box, $content);
    }
    if (hash_file('sha256', $box) !== BOX_SHA256) {
        fail(sprintf('%s does not match the pinned SHA-256; delete it to download it again.', $box));
    }

    return $box;
}

if (PHP_VERSION_ID < 80200) {
    fail(sprintf('Box %s needs PHP 8.2 or later; this is PHP %s.', BOX_VERSION, PHP_VERSION));
}

$buildDirectory = $root . '/build/out';
removeTree($buildDirectory);
$bootstrapFile = (new ContainerFactory(
    $root . '/config/services.php',
    ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
))->dump($buildDirectory);
fwrite(STDOUT, sprintf("Compiled the container into %s\n", dirname($bootstrapFile)));

$command = [PHP_BINARY, '-d', 'phar.readonly=0', box($root), 'compile', '--no-interaction', '--working-dir=' . $root];
$composer = getenv('COMPOSER_BINARY');
if (is_string($composer) && $composer !== '') {
    $command[] = '--composer-bin=' . $composer;
}
passthru(implode(' ', array_map('escapeshellarg', $command)), $exitCode);
if ($exitCode !== 0) {
    fail(sprintf('Box failed with exit code %d.', $exitCode));
}

$phar = $root . '/build/key-rotator.phar';
if (!is_file($phar)) {
    fail('Box reported success but build/key-rotator.phar does not exist.');
}
fwrite(STDOUT, sprintf("Built %s (%d bytes)\n", $phar, (int) filesize($phar)));
