<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;

/**
 * One holder's exclusive lock on the state directory: an flock() on its `.lock` file, taken without
 * waiting. Another process, or another holder in the same process, that holds it makes taking it fail.
 * The operating system releases the lock when the process ends, however it ends, so a crashed run never
 * leaves the directory locked. The file itself stays: removing it would let two processes lock two
 * different files of the same name.
 *
 * The lock file is opened only after the state directory and the file's path were found safe
 * ({@see StateDirectoryTrust}), and the file opened is checked to be that very file, never one a
 * symbolic link points to.
 *
 * Created through {@see StateDirectoryLockFactory}, one per run store.
 */
final class StateDirectoryLock
{
    /**
     * @var resource|null the open lock file while the lock is held
     */
    private $handle = null;

    public function __construct(
        private readonly RunDirectoryLayout $layout,
        private readonly StateDirectoryTrust $trust,
        private readonly FileOperations $files,
    ) {}

    /**
     * Takes the lock; taking it again while holding it changes nothing.
     *
     * @throws RunLocked               when another holder has it
     * @throws UntrustedStateDirectory when the state directory or the lock file is not safe
     */
    public function acquire(): void
    {
        if ($this->handle !== null) {
            return;
        }
        $this->layout->ensureStateDirectory();
        $file = $this->layout->lockFile();
        $previous = umask(0077);
        try {
            $handle = $this->files->attempt(sprintf('open "%s"', $file), static fn() => fopen($file, 'cb'));
        } finally {
            umask($previous);
        }
        try {
            $this->trust->verifyOpenedFile($file, $handle);
        } catch (UntrustedStateDirectory $untrusted) {
            fclose($handle);

            throw $untrusted;
        }

        if (!flock($handle, LOCK_EX | LOCK_NB)) {
            fclose($handle);

            throw new RunLocked(sprintf(
                'Another process holds the lock %s: one run at a time works on a Magento root. Wait for it to finish.',
                $file,
            ));
        }
        $this->handle = $handle;
    }

    /**
     * Releases the lock, if this holder has it.
     */
    public function release(): void
    {
        if ($this->handle === null) {
            return;
        }
        flock($this->handle, LOCK_UN);
        fclose($this->handle);
        $this->handle = null;
    }
}
