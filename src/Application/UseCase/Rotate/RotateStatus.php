<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate;

/**
 * How a rotation call ended:
 * - dry_run: the plan was scanned; nothing was locked or written;
 * - reencrypted: the key is appended, the web tier holds it and the values moved onto it;
 * - awaiting_web_tier: the key is appended but the web tier did not confirm it within the wait; the run
 *   waits and the same command resumes it once the web tier reloads;
 * - refused: a safety check stopped the call; the result names every reason.
 */
enum RotateStatus: string
{
    case DryRun = 'dry_run';
    case Reencrypted = 'reencrypted';
    case AwaitingWebTier = 'awaiting_web_tier';
    case Refused = 'refused';
}
