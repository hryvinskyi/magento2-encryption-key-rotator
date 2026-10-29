<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

/**
 * The exit codes of every command, the same for all of them:
 * - 0: done, or nothing to do (a dry run, a run already rolled back, nothing to purge);
 * - 1: an unexpected error; what was written up to it is recorded in the run, and the command can be run
 *   again;
 * - 2: waiting for the web tier, which did not confirm the key ring in time; the same command resumes the
 *   run once the web tier reloaded;
 * - 3: refused by a safety check or by an option; nothing was written past the point the check guards.
 */
final class ExitCode
{
    public const DONE = 0;
    public const UNEXPECTED = 1;
    public const WAITING = 2;
    public const REFUSED = 3;

    private function __construct() {}
}
