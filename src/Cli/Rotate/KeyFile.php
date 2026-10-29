<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Rotate;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;

/**
 * Reads the ring entry of a key the operator supplies for a rotation from a file. A key is never taken
 * from an option value, which every user of the host sees in the process list and the shell history
 * keeps; the file must belong to the user the tool runs as and be readable by its owner only, so no
 * other user could have read the key, or put one there for the tool to append. The entry is the file's
 * content without the surrounding whitespace (a ring entry holds none).
 */
final class KeyFile
{
    public function __construct(
        private readonly RuntimeUser $user,
    ) {}

    /**
     * @throws OptionRefused when the file is missing, unreadable, owned by another user, readable by its
     *                       group or others, or empty
     */
    public function read(string $path): string
    {
        clearstatcache(true, $path);
        if (!is_file($path) || !is_readable($path)) {
            throw new OptionRefused(sprintf('--key-file: %s is not a readable file.', $path));
        }
        $owner = fileowner($path);
        $uid = $this->user->effectiveUid();
        if ($owner === false || $owner !== $uid) {
            throw new OptionRefused(sprintf(
                '--key-file: %s belongs to user %s, but the tool runs as user %d; a key file must belong to the user that appends its key: chown it. The key was not read.',
                $path,
                $owner === false ? 'unknown' : (string) $owner,
                $uid,
            ));
        }
        $permissions = fileperms($path);
        if ($permissions === false) {
            throw new OptionRefused(sprintf('--key-file: the permissions of %s cannot be read.', $path));
        }
        if (($permissions & 0o077) !== 0) {
            throw new OptionRefused(sprintf(
                '--key-file: %s is readable or writable by its group or others (mode %04o); a key file must be private to its owner: chmod 600 it. The key was not read.',
                $path,
                $permissions & 0o777,
            ));
        }
        $content = file_get_contents($path);
        $entry = $content === false ? '' : trim($content);
        if ($entry === '') {
            throw new OptionRefused(sprintf('--key-file: %s holds no key.', $path));
        }

        return $entry;
    }
}
