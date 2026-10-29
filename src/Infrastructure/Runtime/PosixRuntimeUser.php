<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;

/**
 * The effective user id of the tool's process, from the POSIX extension when PHP has it, otherwise from
 * `id -u`.
 */
final class PosixRuntimeUser implements RuntimeUser
{
    public function __construct(
        private readonly IdCommandUserId $idCommand,
    ) {}

    /**
     * {@inheritDoc}
     *
     * @throws UserIdUnavailable when PHP has no POSIX functions and `id -u` gives no user id
     */
    public function effectiveUid(): int
    {
        if (extension_loaded('posix')) {
            return posix_geteuid();
        }

        return $this->idCommand->effectiveUid();
    }
}
