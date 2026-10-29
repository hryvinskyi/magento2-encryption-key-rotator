<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;

/**
 * Decides whether the state directory, and each entry below it, may be trusted with key material.
 *
 * On a store, `var/` is often writable by the web server's group, which is exactly the account a PHP
 * vulnerability hands an attacker. Whoever can write the state directory or the directory above it can
 * plant a run record or kept keys, swap a run directory for a symbolic link so that removing it zeroes
 * and deletes files elsewhere, or redirect the lock file or a mode change. So, on every use and before
 * anything is read or written there:
 *
 * - the state directory, when it exists, is a real directory (not a symbolic link), owned by the user
 *   the tool runs as, and writable by nobody else (no group or other write bit);
 * - the directory above it (the nearest one that exists, when the state directory is still to be
 *   created) is writable by nobody else unless it is sticky, as `/tmp` is, and is owned by the tool's
 *   user or by root. Through a symbolic link, the directory it points to is the one judged;
 * - every entry below the state directory the tool uses (a run directory, the probe directory, the lock
 *   file, a run's files) is, when it exists, neither a symbolic link nor another user's; a directory
 *   among them is writable by nobody else.
 *
 * Once the state directory and its parent pass, only the tool's user (and root) can create, rename or
 * replace an entry in it, so an entry found safe stays safe until the tool itself changes it.
 */
final class StateDirectoryTrust
{
    private const TYPE_MASK = 0170000;
    private const TYPE_LINK = 0120000;
    private const TYPE_DIRECTORY = 0040000;
    private const TYPE_FILE = 0100000;
    private const GROUP_OR_OTHER_WRITE = 0022;
    private const STICKY = 01000;
    private const ROOT = 0;

    private const MOVE_IT = 'Pass --state-dir with a directory only the user running the tool can write, which PHP-FPM can also enter '
        . 'when the FastCGI probe is used: for example a directory owned by root or by that user, outside the document root '
        . 'and outside var/.';

    public function __construct(
        private readonly RuntimeUser $user,
    ) {}

    /**
     * @param string $directory the absolute path of the state directory; it may not exist yet
     *
     * @throws UntrustedStateDirectory when it or the directory above it may be written by someone else
     */
    public function verifyStateDirectory(string $directory): void
    {
        $this->verifyParent($directory);
        $status = $this->linkStatus($directory);
        if ($status === null) {
            return;
        }
        $uid = $this->user->effectiveUid();
        if ($this->type($status) === self::TYPE_LINK) {
            throw new UntrustedStateDirectory(sprintf('The state directory %s is a symbolic link; it is never followed. %s', $directory, self::MOVE_IT));
        }
        if ($this->type($status) !== self::TYPE_DIRECTORY) {
            throw new UntrustedStateDirectory(sprintf('The state directory %s is not a directory. %s', $directory, self::MOVE_IT));
        }
        if ($status['uid'] !== $uid) {
            throw new UntrustedStateDirectory(sprintf(
                'The state directory %s belongs to user id %d, not to user id %d the tool runs as. %s',
                $directory,
                $status['uid'],
                $uid,
                self::MOVE_IT,
            ));
        }
        if (($status['mode'] & self::GROUP_OR_OTHER_WRITE) !== 0) {
            throw new UntrustedStateDirectory(sprintf(
                'The state directory %s (mode %04o) can be written by its group or by others. %s',
                $directory,
                $status['mode'] & 07777,
                self::MOVE_IT,
            ));
        }
    }

    /**
     * @param string $path a directory below the state directory: a run directory or the probe directory
     *
     * @throws UntrustedStateDirectory when it is a symbolic link, not a directory, another user's or
     *                                 writable by someone else
     */
    public function verifyDirectory(string $path): void
    {
        $this->verifiedDirectory($path);
    }

    /**
     * @param string $path a file below the state directory: the lock file or a run's file
     *
     * @throws UntrustedStateDirectory when it is a symbolic link, not a regular file or another user's
     */
    public function verifyFile(string $path): void
    {
        $status = $this->linkStatus($path);
        if ($status === null) {
            return;
        }
        $this->verifyEntry($path, $status, self::TYPE_FILE, 'a regular file');
    }

    /**
     * Verifies that a file opened by path is the trusted entry at that path, not one swapped in between.
     *
     * @param resource $handle the file opened from the path
     *
     * @throws UntrustedStateDirectory when the path is not a trusted file, or is no longer the file opened
     */
    public function verifyOpenedFile(string $path, $handle): void
    {
        $status = $this->linkStatus($path);
        $opened = fstat($handle);
        if ($status === null || $opened === false) {
            throw new UntrustedStateDirectory(sprintf('The file %s disappeared while the tool opened it.', $path));
        }
        $this->verifyEntry($path, $status, self::TYPE_FILE, 'a regular file');
        if ($opened['dev'] !== $status['dev'] || $opened['ino'] !== $status['ino']) {
            throw new UntrustedStateDirectory(sprintf('The file %s was replaced while the tool opened it; nothing was written to it.', $path));
        }
    }

    /**
     * Verifies a directory below the state directory and returns what identifies it, so that a later
     * {@see verifySameDirectory()} notices a directory replaced in between.
     *
     * @return array{dev: int, ino: int, uid: int}|null null when the directory does not exist
     *
     * @throws UntrustedStateDirectory as {@see verifyDirectory()}
     */
    public function verifiedDirectory(string $path): ?array
    {
        $status = $this->linkStatus($path);
        if ($status === null) {
            return null;
        }
        $this->verifyEntry($path, $status, self::TYPE_DIRECTORY, 'a directory');
        if (($status['mode'] & self::GROUP_OR_OTHER_WRITE) !== 0) {
            throw new UntrustedStateDirectory(sprintf(
                'The directory %s (mode %04o) can be written by its group or by others, which the tool never allows; inspect it before going on.',
                $path,
                $status['mode'] & 07777,
            ));
        }

        return ['dev' => $status['dev'], 'ino' => $status['ino'], 'uid' => $status['uid']];
    }

    /**
     * @param array{dev: int, ino: int, uid: int} $identity what {@see verifiedDirectory()} returned for it
     *
     * @throws UntrustedStateDirectory when the path is no longer that directory
     */
    public function verifySameDirectory(string $path, array $identity): void
    {
        if ($this->verifiedDirectory($path) !== $identity) {
            throw new UntrustedStateDirectory(sprintf('The directory %s was replaced while the tool was removing it; nothing more was removed.', $path));
        }
    }

    /**
     * @param array{mode: int, uid: int} $status
     */
    private function verifyEntry(string $path, array $status, int $type, string $what): void
    {
        $uid = $this->user->effectiveUid();
        if ($this->type($status) === self::TYPE_LINK) {
            throw new UntrustedStateDirectory(sprintf(
                '%s is a symbolic link, which the tool never creates and never follows: someone else changed the state directory. Inspect it before going on.',
                $path,
            ));
        }
        if ($this->type($status) !== $type) {
            throw new UntrustedStateDirectory(sprintf('%s is not %s; inspect the state directory before going on.', $path, $what));
        }
        if ($status['uid'] !== $uid) {
            throw new UntrustedStateDirectory(sprintf(
                '%s belongs to user id %d, not to user id %d the tool runs as: someone else changed the state directory. Inspect it before going on.',
                $path,
                $status['uid'],
                $uid,
            ));
        }
    }

    private function verifyParent(string $directory): void
    {
        $parent = dirname($directory);
        while (!file_exists($parent) && dirname($parent) !== $parent) {
            $parent = dirname($parent);
        }
        clearstatcache(true, $parent);
        $status = @stat($parent);
        if ($status === false) {
            throw new UntrustedStateDirectory(sprintf('The directory %s above the state directory cannot be inspected. %s', $parent, self::MOVE_IT));
        }
        if (($status['mode'] & self::GROUP_OR_OTHER_WRITE) !== 0 && ($status['mode'] & self::STICKY) === 0) {
            throw new UntrustedStateDirectory(sprintf(
                'The directory %s (mode %04o) above the state directory can be written by its group or by others, '
                . 'who could replace the state directory. %s',
                $parent,
                $status['mode'] & 07777,
                self::MOVE_IT,
            ));
        }
        $uid = $this->user->effectiveUid();
        if ($status['uid'] !== $uid && $status['uid'] !== self::ROOT) {
            throw new UntrustedStateDirectory(sprintf(
                'The directory %s above the state directory belongs to user id %d, who could replace the state directory; '
                . 'the tool runs as user id %d. %s',
                $parent,
                $status['uid'],
                $uid,
                self::MOVE_IT,
            ));
        }
    }

    /**
     * The entry's own status, never its link target's.
     *
     * @return array{dev: int, ino: int, mode: int, uid: int}|null null when nothing is at the path
     */
    private function linkStatus(string $path): ?array
    {
        clearstatcache(true, $path);
        $status = @lstat($path);
        if ($status === false) {
            return null;
        }

        return ['dev' => $status['dev'], 'ino' => $status['ino'], 'mode' => $status['mode'], 'uid' => $status['uid']];
    }

    /**
     * @param array{mode: int} $status
     */
    private function type(array $status): int
    {
        return $status['mode'] & self::TYPE_MASK;
    }
}
