<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Run\CorruptRunFile;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;

/**
 * A JSON file of a run directory, readable by its owner only (0600) and always replaced atomically: a
 * reader never finds half a record, whatever moment a crash happens at.
 */
final class PrivateJsonFile
{
    public function __construct(
        private readonly AtomicFileWriter $writer,
        private readonly FileOperations $files,
    ) {}

    public function exists(string $path): bool
    {
        clearstatcache(true, $path);

        return is_file($path);
    }

    /**
     * @param string $path the file, which must exist
     * @param string $what what the file holds, for the message of a corrupt file: `the record of run …`
     *
     * @return mixed the decoded JSON, objects as arrays
     *
     * @throws CorruptRunFile when the file is not JSON
     */
    public function read(string $path, string $what): mixed
    {
        $json = $this->files->attempt(sprintf('read "%s"', $path), static fn(): string|false => file_get_contents($path));
        try {
            return json_decode($json, true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException $invalid) {
            throw new CorruptRunFile(sprintf('%s is corrupt: %s is not valid JSON.', ucfirst($what), $path), 0, $invalid);
        }
    }

    /**
     * @param array<mixed> $data
     */
    public function write(string $path, array $data): void
    {
        $json = json_encode($data, JSON_THROW_ON_ERROR | JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_PRESERVE_ZERO_FRACTION) . "\n";
        $this->writer->write($path, $json, RunDirectoryLayout::FILE_MODE);
    }
}
