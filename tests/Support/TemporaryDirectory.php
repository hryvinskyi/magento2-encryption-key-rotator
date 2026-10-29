<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

/**
 * Creates and removes scratch directories for tests that write files.
 */
final class TemporaryDirectory
{
    public static function create(string $prefix): string
    {
        $path = sys_get_temp_dir() . '/' . $prefix . '-' . bin2hex(random_bytes(8));
        if (!mkdir($path, 0700, true)) {
            throw new \RuntimeException(sprintf('Cannot create "%s".', $path));
        }
        $real = realpath($path);
        if ($real === false) {
            throw new \RuntimeException(sprintf('Cannot resolve "%s".', $path));
        }

        return $real;
    }

    public static function remove(string $path): void
    {
        if (is_link($path) || is_file($path)) {
            unlink($path);

            return;
        }
        if (!is_dir($path)) {
            return;
        }
        $entries = scandir($path);
        if ($entries === false) {
            throw new \RuntimeException(sprintf('Cannot read "%s".', $path));
        }
        foreach ($entries as $entry) {
            if ($entry !== '.' && $entry !== '..') {
                self::remove($path . '/' . $entry);
            }
        }
        rmdir($path);
    }
}
