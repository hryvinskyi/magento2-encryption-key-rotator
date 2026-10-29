<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge;

/**
 * How a purge call ended:
 * - purged: the run's journal and run directory, its kept keys with it, are gone; the run can no longer
 *   be undone and the state directory no longer knows it;
 * - nothing_to_purge: the state directory holds no such run (a purge repeated after it finished ends
 *   here); nothing was done;
 * - refused: a safety check stopped the call; the result names every reason and nothing was deleted.
 */
enum PurgeStatus: string
{
    case Purged = 'purged';
    case NothingToPurge = 'nothing_to_purge';
    case Refused = 'refused';
}
