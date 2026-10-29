<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;

/**
 * Where a run store keeps its files, below the state directory the command was given:
 *
 *     <state directory>/            created 0711 when missing: others may pass through, never list it
 *         .lock                     held with flock() by the process working on the root
 *         probe/                    0711, where the FastCGI probe puts its file for the PHP-FPM pool
 *         <run id>/                 0700, one per run
 *             run.json              0600, the run record
 *             env.php.bak           0600, the deployment configuration as it was when the run began
 *             keys.json             0600, the ring entries the run keeps to undo itself
 *             placeholders.json     0600, the placeholders a pending retirement writes
 *
 * The state directory is asked for on every call, never remembered, and every path this layout hands
 * out has been checked by {@see StateDirectoryTrust} first: the state directory and the directory above
 * it can be written by nobody but the tool's user, and the entry itself, when it exists, is neither a
 * symbolic link nor another user's. A mode is only ever set on a directory checked that way, so it is
 * never applied through a symbolic link.
 *
 * Directories are created with a umask that leaves them to their owner, so no file of a run is ever
 * readable by anyone else, not even for the moment between its creation and a chmod. The state directory
 * and the probe directory alone are opened to 0711: a web-tier probe script below them must be reachable
 * by a PHP-FPM pool running as another user, which can open a file whose name it is given but cannot
 * list the directories or enter a run's 0700 directory.
 */
final class RunDirectoryLayout
{
    public const RUN_FILE = 'run.json';
    public const BACKUP_FILE = 'env.php.bak';
    public const KEYS_FILE = 'keys.json';
    public const PLACEHOLDERS_FILE = 'placeholders.json';
    public const LOCK_FILE = '.lock';
    public const PROBE_DIRECTORY = 'probe';

    public const DIRECTORY_MODE = 0700;
    public const STATE_DIRECTORY_MODE = 0711;
    public const PROBE_DIRECTORY_MODE = 0711;
    public const FILE_MODE = 0600;

    private const PERMISSION_BITS = 0777;
    private const RUN_ID_SHAPE = '/^[0-9a-f]{32}$/D';

    public function __construct(
        private readonly StateDirectoryProvider $stateDirectory,
        private readonly StateDirectoryTrust $trust,
        private readonly FileOperations $files,
    ) {}

    /**
     * @throws UntrustedStateDirectory when the state directory or the directory above it is not safe
     */
    public function stateDirectory(): string
    {
        $directory = $this->stateDirectory->directory();
        $directory = $directory === '/' ? $directory : rtrim($directory, '/');
        $this->trust->verifyStateDirectory($directory);

        return $directory;
    }

    /**
     * @throws UntrustedStateDirectory when the state directory or the lock file is not safe
     */
    public function lockFile(): string
    {
        $file = $this->stateDirectory() . '/' . self::LOCK_FILE;
        $this->trust->verifyFile($file);

        return $file;
    }

    /**
     * @throws UntrustedStateDirectory when the state directory or the run directory is not safe
     */
    public function runDirectory(RunId $id): string
    {
        $directory = $this->stateDirectory() . '/' . $id->toString();
        $this->trust->verifyDirectory($directory);

        return $directory;
    }

    /**
     * @param string $name one of the file names of a run directory
     *
     * @throws UntrustedStateDirectory when the state directory, the run directory or the file is not safe
     */
    public function runFile(RunId $id, string $name): string
    {
        $file = $this->runDirectory($id) . '/' . $name;
        $this->trust->verifyFile($file);

        return $file;
    }

    /**
     * The ids of the runs the state directory holds a run record for, in ascending order. A run directory
     * without a record (one whose removal was interrupted) holds no run.
     *
     * @return list<string>
     *
     * @throws UntrustedStateDirectory when the state directory, a run directory or a run record is not safe
     * @throws FilesystemFailure       when a directory cannot be listed, created or given its mode
     */
    public function runIds(): array
    {
        $directory = $this->stateDirectory();
        if (!is_dir($directory)) {
            return [];
        }
        $entries = $this->files->attempt(sprintf('list "%s"', $directory), static fn(): array|false => scandir($directory));

        $ids = [];
        foreach ($entries as $entry) {
            if (preg_match(self::RUN_ID_SHAPE, $entry) !== 1) {
                continue;
            }
            $this->trust->verifyDirectory($directory . '/' . $entry);
            $record = $directory . '/' . $entry . '/' . self::RUN_FILE;
            $this->trust->verifyFile($record);
            if (is_file($record)) {
                $ids[] = $entry;
            }
        }
        sort($ids);

        return $ids;
    }

    /**
     * Creates the state directory, mode 0711, when it does not exist; an existing one keeps its mode.
     *
     * @throws UntrustedStateDirectory when the state directory or the directory above it is not safe
     * @throws FilesystemFailure       when a directory cannot be listed, created or given its mode
     */
    public function ensureStateDirectory(): string
    {
        $directory = $this->stateDirectory();
        if (is_dir($directory)) {
            return $directory;
        }
        $this->createDirectory($directory, self::STATE_DIRECTORY_MODE, true);
        $this->trust->verifyStateDirectory($directory);
        $this->setMode($directory, self::STATE_DIRECTORY_MODE);

        return $directory;
    }

    /**
     * Creates the run's directory, mode 0700, and the state directory above it, when they do not exist.
     *
     * @throws UntrustedStateDirectory when the state directory or the run directory is not safe
     * @throws FilesystemFailure       when a directory cannot be listed, created or given its mode
     */
    public function ensureRunDirectory(RunId $id): string
    {
        return $this->ensureEntryDirectory($id->toString(), self::DIRECTORY_MODE);
    }

    /**
     * Creates the probe directory, mode 0711, and the state directory above it, when they do not exist;
     * gives an existing one exactly that mode.
     *
     * @throws UntrustedStateDirectory when the state directory or the probe directory is not safe
     * @throws FilesystemFailure       when a directory cannot be listed, created or given its mode
     */
    public function ensureProbeDirectory(): string
    {
        return $this->ensureEntryDirectory(self::PROBE_DIRECTORY, self::PROBE_DIRECTORY_MODE);
    }

    private function ensureEntryDirectory(string $name, int $mode): string
    {
        $directory = $this->ensureStateDirectory() . '/' . $name;
        $this->trust->verifyDirectory($directory);
        if (!is_dir($directory)) {
            $this->createDirectory($directory, $mode, false);
        }
        $this->setMode($directory, $mode);

        return $directory;
    }

    /**
     * Creates the directory, and its missing parents when asked to, with exactly the mode given: the
     * umask is narrowed for the call, so it can never leave a directory more open than asked.
     */
    private function createDirectory(string $directory, int $mode, bool $withParents): void
    {
        $previous = umask(self::PERMISSION_BITS & ~$mode);
        try {
            $this->files->attempt(
                sprintf('create the directory "%s"', $directory),
                static fn(): bool => mkdir($directory, $mode, $withParents) || is_dir($directory),
            );
        } finally {
            umask($previous);
        }
    }

    /**
     * Sets a directory's mode after checking, right before, that the path is the tool's own directory
     * and not a symbolic link to somewhere else.
     */
    private function setMode(string $directory, int $mode): void
    {
        $this->trust->verifyDirectory($directory);
        $this->files->attempt(
            sprintf('give "%s" the mode %04o', $directory, $mode),
            static fn(): bool => chmod($directory, $mode),
        );
    }
}
