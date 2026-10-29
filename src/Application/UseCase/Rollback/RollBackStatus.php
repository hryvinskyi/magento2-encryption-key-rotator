<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

/**
 * How a rollback call ended:
 * - rolled_back: every value is back under the keys of the ring before the run, and the deployment
 *   configuration holds that ring again;
 * - already_rolled_back: the last run was rolled back before; nothing was done;
 * - awaiting_web_tier: a ring write of the rollback is done but the web tier did not confirm it within
 *   the wait; the run stays `rolling_back` and the same command continues it once the web tier reloads;
 * - refused: a safety check stopped the call; the result names every reason. A run that started rolling
 *   back stays `rolling_back`, and only the rollback may continue it.
 */
enum RollBackStatus: string
{
    case RolledBack = 'rolled_back';
    case AlreadyRolledBack = 'already_rolled_back';
    case AwaitingWebTier = 'awaiting_web_tier';
    case Refused = 'refused';
}
