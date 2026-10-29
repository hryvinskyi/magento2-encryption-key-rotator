<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;

/**
 * The commands that change or read a rotation, as the operator types them.
 */
enum RunCommand: string
{
    case Scan = 'scan';
    case Rotate = 'rotate';
    case Retire = 'retire';
    case Rollback = 'rollback';
    case Purge = 'purge';

    /**
     * The commands a run in that state allows next; with no run, a scan or a new rotation.
     *
     * - An interrupted write (`key_pending`, `retire_pending`) is finished by running the interrupted
     *   command again, or undone by a rollback.
     * - While a rollback is in progress, only the rollback may continue.
     * - A finished run (rolled back or purged) leaves the way open for a new rotation.
     *
     * @return list<self>
     */
    public static function allowedAfter(?RunState $state): array
    {
        return match ($state) {
            null, RunState::Purged => [self::Scan, self::Rotate],
            RunState::Started, RunState::KeyPending, RunState::KeyAdded, RunState::WebConfirmed => [self::Rotate, self::Rollback],
            RunState::Reencrypted => [self::Rotate, self::Retire, self::Rollback],
            RunState::RetirePending => [self::Retire, self::Rollback],
            RunState::Retired => [self::Purge, self::Rollback],
            RunState::RollingBack => [self::Rollback],
            RunState::RolledBack => [self::Purge, self::Rotate],
        };
    }
}
