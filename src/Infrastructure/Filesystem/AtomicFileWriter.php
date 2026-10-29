<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem;

/**
 * Replaces a file so that every reader sees either its old content or its new content, never a part
 * of either, and so that the new content survives a crash once the call returns.
 *
 * The bytes go to a temporary file in the same directory, created readable by its owner only, flushed
 * to disk, given the requested mode (and, as far as the process may, the requested owner and group),
 * then renamed over the path; the directory is flushed last, which makes the rename itself durable.
 * Renaming within one directory never crosses a filesystem, so the replacement is atomic.
 *
 * A path that is a symbolic link is replaced by a regular file: to replace a link's target and keep
 * the link, pass the resolved path.
 *
 * The temporary file is named `.<file name>.key-rotator-<24 hex>.tmp`. A process killed between
 * creating it and the rename leaves it behind, holding a full copy of the new content (for the
 * deployment configuration, every key and password in it), so every write first deletes the temporary
 * files of the same path that match exactly that name, and nothing else; a directory of that name is
 * never touched.
 */
final class AtomicFileWriter
{
    private const OWNER_ONLY_UMASK = 0077;
    private const CHUNK = 8192;
    private const TEMPORARY_RANDOM_BYTES = 12;
    private const TEMPORARY_MARK = '.key-rotator-';
    private const TEMPORARY_SUFFIX = '.tmp';

    public function __construct(
        private readonly FileOperations $files,
    ) {}

    /**
     * @param string   $path  the file to replace or create
     * @param string   $bytes its new content
     * @param int      $mode  its permission bits, e.g. 0600
     * @param int|null $owner the user id to give it, when the process may; null keeps the process's
     * @param int|null $group the group id to give it, when the process may; null keeps the process's
     *
     * @throws FilesystemFailure when the file cannot be written; the path then keeps its old content and
     *                           no temporary file is left behind
     */
    public function write(string $path, string $bytes, int $mode, ?int $owner = null, ?int $group = null): void
    {
        $directory = dirname($path);
        $name = basename($path);
        $this->removeStaleTemporaries($directory, $name);
        $temporary = $directory . '/.' . $name . self::TEMPORARY_MARK . bin2hex(random_bytes(self::TEMPORARY_RANDOM_BYTES)) . self::TEMPORARY_SUFFIX;

        try {
            $this->writeTemporary($temporary, $bytes, $mode);
            $this->adoptOwnership($temporary, $owner, $group);
            $this->files->attempt(
                sprintf('rename "%s" over "%s"', $temporary, $path),
                static fn(): bool => rename($temporary, $path),
            );
        } catch (FilesystemFailure $failure) {
            $this->files->bestEffort(static fn(): bool => !file_exists($temporary) || unlink($temporary));

            throw $failure;
        }

        $this->syncDirectory($directory);
    }

    /**
     * Deletes the temporary files an interrupted write of the same file left in the directory; one that
     * cannot be deleted stays, and the next write tries again. A directory that cannot be listed has
     * nothing to delete here: the write that follows reports why it cannot create its file there.
     */
    private function removeStaleTemporaries(string $directory, string $name): void
    {
        try {
            $entries = $this->files->attempt(sprintf('list "%s"', $directory), static fn(): array|false => scandir($directory));
        } catch (FilesystemFailure) {
            return;
        }
        $pattern = sprintf(
            '/^\.%s%s[0-9a-f]{%d}%s$/D',
            preg_quote($name, '/'),
            preg_quote(self::TEMPORARY_MARK, '/'),
            self::TEMPORARY_RANDOM_BYTES * 2,
            preg_quote(self::TEMPORARY_SUFFIX, '/'),
        );
        foreach ($entries as $entry) {
            $stale = $directory . '/' . $entry;
            if (preg_match($pattern, $entry) === 1 && (is_link($stale) || !is_dir($stale))) {
                $this->files->bestEffort(static fn(): bool => unlink($stale));
            }
        }
    }

    private function writeTemporary(string $temporary, string $bytes, int $mode): void
    {
        $previous = umask(self::OWNER_ONLY_UMASK);
        try {
            $handle = $this->files->attempt(sprintf('create "%s"', $temporary), static fn() => fopen($temporary, 'xb'));
        } finally {
            umask($previous);
        }

        try {
            $length = strlen($bytes);
            $written = 0;
            while ($written < $length) {
                $part = substr($bytes, $written, self::CHUNK);
                $written += $this->files->attempt(
                    sprintf('write "%s"', $temporary),
                    static fn(): int|false => fwrite($handle, $part) ?: false,
                );
            }
            $this->files->attempt(sprintf('flush "%s"', $temporary), static fn(): bool => fflush($handle));
            $this->files->attempt(sprintf('sync "%s" to disk', $temporary), static fn(): bool => fsync($handle));
        } finally {
            fclose($handle);
        }

        $this->files->attempt(
            sprintf('give "%s" the mode %04o', $temporary, $mode),
            static fn(): bool => chmod($temporary, $mode),
        );
    }

    /**
     * Gives the file the owner and group asked for. Only a process running as root may give a file away,
     * and a non-root process may only pick one of its own groups: what the process may not do is left
     * as it is, never failed.
     */
    private function adoptOwnership(string $path, ?int $owner, ?int $group): void
    {
        clearstatcache(true, $path);
        if ($owner !== null && fileowner($path) !== $owner) {
            $this->files->bestEffort(static fn(): bool => chown($path, $owner));
        }
        if ($group !== null && filegroup($path) !== $group) {
            $this->files->bestEffort(static fn(): bool => chgrp($path, $group));
        }
    }

    /**
     * Flushes the directory entry of a rename to disk. A filesystem that cannot sync a directory still
     * renamed atomically; only the durability across a power loss is then left to the filesystem.
     */
    private function syncDirectory(string $directory): void
    {
        $this->files->bestEffort(static function () use ($directory): bool {
            $handle = fopen($directory, 'rb');
            if ($handle === false) {
                return false;
            }
            $synced = fsync($handle);
            fclose($handle);

            return $synced;
        });
    }
}
