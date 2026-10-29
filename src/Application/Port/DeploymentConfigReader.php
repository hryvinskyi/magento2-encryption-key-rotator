<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * Reads the store's configuration files: the deployment configuration (`app/etc/env.php`) and,
 * read-only, the committed configuration (`app/etc/config.php`). Every call reads the files as they are
 * now; nothing is cached between calls, so a change made by another writer is always seen.
 */
interface DeploymentConfigReader
{
    /**
     * The shortest string counted as a secret by its name; shorter ones are too common to hide.
     */
    public const SECRET_MIN_LENGTH = 8;

    /**
     * The words that mark a path segment, and so the string under it, as secret.
     */
    public const SECRET_SEGMENT_WORDS = ['password', 'pass', 'secret', 'key', 'token'];

    /**
     * The key ring of `crypt/key`.
     *
     * @throws DeploymentConfigUnreadable when the file cannot be read or holds no `crypt/key`
     * @throws InvalidKeyRing             when the entries do not form a key ring
     * @throws InvalidKey                 when an entry that is not a placeholder is not a usable key
     */
    public function keyRing(): KeyRing;

    /**
     * The default database connection and the table prefix.
     *
     * @throws DeploymentConfigUnreadable when the file cannot be read or names no default connection
     */
    public function databaseSettings(): DatabaseSettings;

    /**
     * Every value of the deployment configuration's `system` section that is a ciphertext.
     *
     * @return list<SystemValue> each with the source {@see \Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource::Env}
     *
     * @throws DeploymentConfigUnreadable when the file cannot be read
     */
    public function systemValues(): array;

    /**
     * Every value of the committed configuration's `system` section that is a ciphertext; empty when the
     * store has no committed configuration file.
     *
     * @return list<SystemValue> each with the source {@see \Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource::Committed}
     *
     * @throws DeploymentConfigUnreadable when the file exists but cannot be read
     */
    public function committedSystemValues(): array;

    /**
     * The user id owning the deployment configuration file (the file a symbolic link points to).
     *
     * @throws DeploymentConfigUnreadable when the owner cannot be read
     */
    public function ownerUid(): int;

    /**
     * Whether the deployment configuration holds only literal data: arrays, strings, numbers, booleans
     * and null, without a function call, a variable, a constant or an include. Only such a file can be
     * rewritten without baking values of the environment into it.
     *
     * @throws DeploymentConfigUnreadable when the file cannot be read
     */
    public function holdsOnlyLiteralData(): bool;

    /**
     * Whether this process can replace the deployment configuration: the real file (the one a symbolic
     * link points to) and the directory holding it are both writable, since the file is replaced by a
     * rename inside that directory.
     *
     * @throws DeploymentConfigUnreadable when the file does not exist
     */
    public function isWritable(): bool;

    /**
     * Every string of the deployment configuration that a name marks as secret: a string of at least
     * {@see self::SECRET_MIN_LENGTH} characters whose path holds a segment containing one of
     * {@see self::SECRET_SEGMENT_WORDS}, ignoring case. They are what an error message must never show.
     *
     * @return list<string> each string once, in the order of the file
     *
     * @throws DeploymentConfigUnreadable when the file cannot be read
     */
    public function secretStrings(): array;
}
