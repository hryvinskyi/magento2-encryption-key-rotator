<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem;

/**
 * Runs PHP's native file functions so that a failure is an exception, never a warning printed on the
 * tool's output: a `false` result, together with the warning the function raised, becomes a
 * {@see FilesystemFailure} naming what was attempted.
 */
final class FileOperations
{
    /**
     * Runs one operation that must succeed.
     *
     * @template T
     *
     * @param string                $attempted what the operation does, for the message: `rename "a" over "b"`
     * @param \Closure(): (T|false) $operation the native call; `false` means it failed
     *
     * @return T
     *
     * @throws FilesystemFailure when the operation returns false
     */
    public function attempt(string $attempted, \Closure $operation): mixed
    {
        [$result, $warning] = $this->trapped($operation);
        if ($result === false) {
            throw new FilesystemFailure(sprintf('Cannot %s%s.', $attempted, $warning === null ? '' : ': ' . $warning));
        }

        return $result;
    }

    /**
     * Runs one operation whose failure is acceptable, such as giving a file back to its owner when the
     * process may not, without a warning on the output.
     *
     * @param \Closure(): bool $operation the native call
     *
     * @return bool whether it succeeded
     */
    public function bestEffort(\Closure $operation): bool
    {
        [$result] = $this->trapped($operation);

        return $result;
    }

    /**
     * @template R
     *
     * @param \Closure(): R $operation
     *
     * @return array{R, string|null} the result and the last warning raised, if any
     */
    private function trapped(\Closure $operation): array
    {
        $warning = null;
        set_error_handler(static function (int $level, string $message) use (&$warning): bool {
            $warning = $message;

            return true;
        });
        try {
            $result = $operation();
        } finally {
            restore_error_handler();
        }

        return [$result, $warning];
    }
}
