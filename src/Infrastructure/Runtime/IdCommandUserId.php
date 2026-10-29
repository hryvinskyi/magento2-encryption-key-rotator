<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessFactory;
use Symfony\Component\Process\Exception\ExceptionInterface as ProcessException;

/**
 * Reads the effective user id of the tool's process from `id -u`, for a PHP built without the POSIX
 * functions. `id` runs as a child of the tool and therefore with its effective user.
 */
final class IdCommandUserId
{
    public const TIMEOUT_SECONDS = 5.0;

    /**
     * @param string $id the `id` executable, looked up on the PATH unless it is a path
     */
    public function __construct(
        private readonly ProcessFactory $processes,
        private readonly string $id = 'id',
    ) {}

    /**
     * @throws UserIdUnavailable when `id -u` cannot run, fails or prints no user id
     */
    public function effectiveUid(): int
    {
        $process = $this->processes->create([$this->id, '-u'], null, self::TIMEOUT_SECONDS);
        try {
            $process->run();
        } catch (ProcessException $failure) {
            throw new UserIdUnavailable('The effective user id cannot be read: `id -u` could not run.', 0, $failure);
        }

        $output = trim($process->getOutput());
        if (!$process->isSuccessful() || preg_match('/^\d+$/D', $output) !== 1) {
            throw new UserIdUnavailable('The effective user id cannot be read: `id -u` failed or printed no user id.');
        }

        return (int) $output;
    }
}
