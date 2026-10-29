<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Symfony\Component\Process\Process;

/**
 * Scratch Magento roots for tests of the configuration files: a temporary directory with `app/etc/`,
 * holding copies of the configuration fixtures, and an independent way to evaluate a configuration file
 * in a fresh PHP process.
 *
 * The fixtures under `tests/Fixtures/env/` carry the `.fixture` suffix so the coding standard and the
 * static analysis, which read every `.php` file of the test tree, leave them in the store's own format.
 */
final class ScratchMagentoRoot
{
    public const RETIRED_SLOT_AND_PREFIX = 'env-retired-slot-and-prefix.php.fixture';
    public const WITH_GETENV = 'env-with-getenv.php.fixture';
    public const RETURNING_NON_ARRAY = 'env-returning-non-array.php.fixture';
    public const COMMITTED_WITH_ENCRYPTED_VALUE = 'config-with-encrypted-value.php.fixture';

    public static function fixture(string $name): string
    {
        return dirname(__DIR__) . '/Fixtures/env/' . $name;
    }

    /**
     * A new root whose `app/etc/env.php` is a copy of the fixture, and whose `app/etc/config.php` is a
     * copy of the committed fixture when one is named.
     */
    public static function create(string $envFixture, ?string $committedFixture = null): string
    {
        $root = TemporaryDirectory::create('key-rotator-root');
        if (!mkdir($root . '/app/etc', 0755, true)) {
            throw new \RuntimeException(sprintf('Cannot create "%s/app/etc".', $root));
        }
        self::copy(self::fixture($envFixture), $root . '/app/etc/env.php');
        if ($committedFixture !== null) {
            self::copy(self::fixture($committedFixture), $root . '/app/etc/config.php');
        }

        return $root;
    }

    /**
     * Evaluates a configuration file in a fresh PHP process of its own, apart from the tool's loader.
     *
     * @return array<mixed>
     */
    public static function evaluate(string $file): array
    {
        $process = new Process([PHP_BINARY, '-d', 'opcache.enable_cli=0', '-r', 'echo serialize(include $argv[1]);', '--', $file]);
        $process->mustRun();
        $data = unserialize($process->getOutput(), ['allowed_classes' => false]);
        if (!is_array($data)) {
            throw new \RuntimeException(sprintf('"%s" does not return an array.', $file));
        }

        return $data;
    }

    /**
     * Every file name in the directory.
     *
     * @return list<string>
     */
    public static function entries(string $directory): array
    {
        $entries = scandir($directory);
        if ($entries === false) {
            throw new \RuntimeException(sprintf('Cannot read "%s".', $directory));
        }

        return array_values(array_diff($entries, ['.', '..']));
    }

    public static function bytes(string $file): string
    {
        clearstatcache(true, $file);
        $bytes = file_get_contents($file);
        if ($bytes === false) {
            throw new \RuntimeException(sprintf('Cannot read "%s".', $file));
        }

        return $bytes;
    }

    private static function copy(string $from, string $to): void
    {
        if (!copy($from, $to)) {
            throw new \RuntimeException(sprintf('Cannot copy "%s" to "%s".', $from, $to));
        }
    }
}
