<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire;

/**
 * How a retirement call ended:
 * - retired: the old keys are replaced by placeholders, the web tier holds that ring and the stragglers
 *   found afterwards moved onto the active key;
 * - awaiting_web_tier: the placeholders are written but the web tier did not confirm them within the
 *   wait; the run stays `retire_pending` and the same command resumes it once the web tier reloads;
 * - refused: a safety check stopped the call; the result names every reason.
 */
enum RetireStatus: string
{
    case Retired = 'retired';
    case AwaitingWebTier = 'awaiting_web_tier';
    case Refused = 'refused';
}
