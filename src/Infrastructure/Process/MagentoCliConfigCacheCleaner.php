<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcomeFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Symfony\Component\Process\Exception\ExceptionInterface as ProcessException;
use Symfony\Component\Process\Exception\ProcessTimedOutException;

/**
 * Cleans the configuration cache through the store's own command line: `bin/magento cache:clean config`
 * in the Magento root, run by the PHP binary that runs the tool, with the tool's environment.
 *
 * Exit code 0 is a clean cache. Anything else is not, with the last lines of the command's error output
 * (its standard output when it wrote no error), each passed through the secret redactor and then cut to
 * a readable length, since the store's errors may quote stored values or connection settings.
 */
final class MagentoCliConfigCacheCleaner implements ConfigCacheCleaner
{
    public const TIMEOUT_SECONDS = 120.0;

    private const LINES = 5;
    private const LINE_LENGTH = 200;

    public function __construct(
        private readonly MagentoRootProvider $roots,
        private readonly ProcessFactory $processes,
        private readonly CacheCleanOutcomeFactory $outcomes,
        private readonly SecretRedactor $redactor,
    ) {}

    public function clean(): CacheCleanOutcome
    {
        $process = $this->processes->create(
            [PHP_BINARY, 'bin/magento', 'cache:clean', 'config'],
            $this->roots->root()->path(),
            self::TIMEOUT_SECONDS,
        );

        try {
            $process->run();
        } catch (ProcessTimedOutException) {
            return $this->outcomes->create(false, sprintf(
                'bin/magento cache:clean config did not finish within %d s and was stopped.',
                (int) self::TIMEOUT_SECONDS,
            ));
        } catch (ProcessException) {
            return $this->outcomes->create(false, 'bin/magento cache:clean config could not be started.');
        }

        $exitCode = $process->getExitCode();
        if ($exitCode === 0) {
            return $this->outcomes->create(true, 'The configuration cache was cleaned.');
        }

        $error = trim($process->getErrorOutput());
        $lines = $this->lastLines($error !== '' ? $error : trim($process->getOutput()));

        return $this->outcomes->create(false, sprintf(
            'bin/magento cache:clean config exited with code %s%s',
            $exitCode === null ? 'unknown' : (string) $exitCode,
            $lines === [] ? '.' : ': ' . implode(' | ', $lines),
        ));
    }

    /**
     * @return list<string>
     */
    private function lastLines(string $output): array
    {
        if ($output === '') {
            return [];
        }
        $lines = array_values(array_filter(
            array_map('trim', preg_split('/\R/', $output) ?: []),
            static fn(string $line): bool => $line !== '',
        ));

        $last = [];
        foreach (array_slice($lines, -self::LINES) as $line) {
            // Redacted before it is cut: a secret cut in half would no longer be recognised.
            $redacted = $this->redactor->redact($line);
            $last[] = strlen($redacted) > self::LINE_LENGTH ? substr($redacted, 0, self::LINE_LENGTH) . '…' : $redacted;
        }

        return $last;
    }
}
