<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;

/**
 * Removes a run directory so its key material does not linger on disk: every file but the run record
 * is overwritten with zeros, flushed, and unlinked; the run record goes last, then the directory.
 *
 * Zeroing before unlinking is best effort: on a journaling or copy-on-write filesystem, or on an SSD
 * that remaps blocks, earlier copies of the bytes may survive on the device.
 *
 * Nothing is zeroed or removed outside the run's own directory. A run directory that is a symbolic
 * link, belongs to another user or can be written by someone else, and an entry in it that is a
 * symbolic link or another user's, is refused before anything is touched ({@see StateDirectoryTrust}).
 * A file is zeroed only once the file opened is known to be the entry checked, and right before each
 * removal the directory is checked to be still the one found at the start (same device, inode and
 * owner), so a directory swapped in the meantime stops the removal.
 *
 * Interrupted at any point, the removal can be repeated: what is left is a directory still holding its
 * run record, or one without a record, which no store lists as a run.
 */
final class RunDirectoryShredder
{
    private const CHUNK = 8192;

    public function __construct(
        private readonly StateDirectoryTrust $trust,
        private readonly FileOperations $files,
    ) {}

    /**
     * @param string $directory  the run directory; nothing happens when it does not exist
     * @param string $lastFile   the name of the file removed last
     *
     * @throws FilesystemFailure       when a file cannot be overwritten or removed, or the directory holds
     *                                 a directory of its own
     * @throws UntrustedStateDirectory when the directory or an entry in it is not the tool's own, or the
     *                                 directory is replaced while it is being removed
     */
    public function destroy(string $directory, string $lastFile): void
    {
        $identity = $this->trust->verifiedDirectory($directory);
        if ($identity === null) {
            return;
        }

        $entries = $this->files->attempt(sprintf('list "%s"', $directory), static fn(): array|false => scandir($directory));
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..' || $entry === $lastFile) {
                continue;
            }
            $path = $directory . '/' . $entry;
            if (is_dir($path) && !is_link($path)) {
                throw new FilesystemFailure(sprintf('Cannot remove "%s": it holds the directory "%s", which a run directory never does.', $directory, $entry));
            }
            $this->trust->verifyFile($path);
            $this->shred($path, $directory, $identity);
        }

        $last = $directory . '/' . $lastFile;
        $this->trust->verifyFile($last);
        if (is_file($last)) {
            $this->trust->verifySameDirectory($directory, $identity);
            $this->files->attempt(sprintf('remove "%s"', $last), static fn(): bool => unlink($last));
        }
        $this->trust->verifySameDirectory($directory, $identity);
        $this->files->attempt(sprintf('remove the directory "%s"', $directory), static fn(): bool => rmdir($directory));
    }

    /**
     * @param array{dev: int, ino: int, uid: int} $identity the run directory as it was found
     */
    private function shred(string $path, string $directory, array $identity): void
    {
        $handle = $this->files->attempt(sprintf('open "%s"', $path), static fn() => fopen($path, 'r+b'));
        try {
            $this->trust->verifyOpenedFile($path, $handle);
            $size = $this->files->attempt(sprintf('inspect "%s"', $path), static fn(): array|false => fstat($handle))['size'];
            for ($done = 0; $done < $size; $done += self::CHUNK) {
                $zeros = str_repeat("\0", min(self::CHUNK, $size - $done));
                $this->files->attempt(sprintf('overwrite "%s"', $path), static fn(): int|false => fwrite($handle, $zeros) ?: false);
            }
            $this->files->attempt(sprintf('flush "%s"', $path), static fn(): bool => fflush($handle));
            $this->files->attempt(sprintf('sync "%s" to disk', $path), static fn(): bool => fsync($handle));
        } finally {
            fclose($handle);
        }
        $this->trust->verifySameDirectory($directory, $identity);
        $this->files->attempt(sprintf('remove "%s"', $path), static fn(): bool => unlink($path));
    }
}
