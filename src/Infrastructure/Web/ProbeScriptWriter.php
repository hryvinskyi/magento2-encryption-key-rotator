<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Web;

/**
 * Names the probe file, puts it in place, takes it away, and clears away the probe files a killed run
 * left behind.
 *
 * A probe file is named `key-rotator-probe-<32 hex>.php`. It is written to `.<its name>.tmp` in the
 * same directory and renamed into place, so the web tier never runs a half-written file; it is readable
 * by everyone (0644), since the web tier's PHP may run as another user.
 *
 * A process killed between writing a probe file and deleting it leaves the file behind. Before a new
 * probe file is written, {@see sweep()} deletes every entry of the directory whose name is exactly that
 * of a probe file or of its temporary file, and nothing else; directories are never touched.
 */
final class ProbeScriptWriter
{
    public const MODE = 0644;

    private const PREFIX = 'key-rotator-probe-';
    private const SUFFIX = '.php';
    private const TEMPORARY_SUFFIX = '.tmp';
    private const RANDOM_BYTES = 16;
    private const PROBE_FILE = '/^key-rotator-probe-[0-9a-f]{32}\.php$/D';
    private const PROBE_LEFTOVER = '/^(?:key-rotator-probe-[0-9a-f]{32}\.php|\.key-rotator-probe-[0-9a-f]{32}\.php\.tmp)$/D';

    /**
     * A new, random probe file name.
     */
    public function newFileName(): string
    {
        return self::PREFIX . bin2hex(random_bytes(self::RANDOM_BYTES)) . self::SUFFIX;
    }

    /**
     * @param string $path   the absolute path of the probe file, named by {@see newFileName()}
     * @param string $source the rendered probe file
     *
     * @throws ProbeUnreachable when the file cannot be written; nothing is left behind
     * @throws \LogicException  when the path is not named as a probe file
     */
    public function write(string $path, #[\SensitiveParameter] string $source): void
    {
        $directory = dirname($path);
        $name = basename($path);
        if (preg_match(self::PROBE_FILE, $name) !== 1) {
            throw new \LogicException(sprintf('"%s" is not named as a probe file; the sweep would never find it.', $name));
        }
        $temporary = $directory . '/.' . $name . self::TEMPORARY_SUFFIX;

        $previous = umask(0077);
        try {
            $handle = @fopen($temporary, 'xb');
        } finally {
            umask($previous);
        }
        if ($handle === false) {
            throw new ProbeUnreachable(sprintf('The probe file cannot be written into %s.', $directory));
        }
        $written = @fwrite($handle, $source);
        fclose($handle);

        if ($written !== strlen($source) || !@chmod($temporary, self::MODE) || !@rename($temporary, $path)) {
            @unlink($temporary);
            throw new ProbeUnreachable(sprintf('The probe file cannot be written into %s.', $directory));
        }
    }

    /**
     * Deletes the probe file and checks it is gone.
     *
     * @return bool whether no file is left at the path
     */
    public function remove(string $path): bool
    {
        clearstatcache(true, $path);
        if (file_exists($path) || is_link($path)) {
            @unlink($path);
        }
        clearstatcache(true, $path);

        return !file_exists($path) && !is_link($path);
    }

    /**
     * Deletes the probe files, and their temporary files, an earlier probe left in the directory.
     *
     * @return list<string> the paths of those that could not be deleted
     */
    public function sweep(string $directory): array
    {
        $entries = @scandir($directory);
        if ($entries === false) {
            return [];
        }

        $left = [];
        foreach ($entries as $entry) {
            $path = $directory . '/' . $entry;
            if (preg_match(self::PROBE_LEFTOVER, $entry) !== 1 || (is_dir($path) && !is_link($path))) {
                continue;
            }
            if (!$this->remove($path)) {
                $left[] = $path;
            }
        }

        return $left;
    }
}
