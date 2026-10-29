<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Process\ProcessFactory;
use Symfony\Component\Process\Exception\ProcessTimedOutException;

/**
 * Evaluates a configuration file of the store (a PHP file that returns an array) in a fresh PHP
 * process and hands back the array it returns.
 *
 * The file is the store's, not the tool's: evaluating it in a subprocess keeps whatever it does out of
 * this process, and the subprocess runs with its opcode cache off, so it reads the file as it is on disk
 * now. The subprocess is the PHP executable running the tool, and no prepend or append file of its
 * configuration runs. The array crosses back as JSON; floats keep their exact value and a float with no
 * fraction stays a float.
 *
 * A failure names the file and what went wrong, never anything the file holds: the subprocess's error
 * output is not passed on, since an error raised by the store's code may carry a configured value.
 */
final class PhpArrayFileLoader
{
    private const TIMEOUT_SECONDS = 60.0;
    private const EXIT_NOT_AN_ARRAY = 3;
    private const EXIT_NOT_ENCODABLE = 4;

    /**
     * Reads the file path on standard input, includes the file with any output it prints discarded, and
     * prints the returned array as JSON.
     */
    private const EVALUATOR = <<<'PHP'
        $file = (string) stream_get_contents(STDIN);
        $level = ob_get_level();
        ob_start();
        $data = include $file;
        while (ob_get_level() > $level) {
            ob_end_clean();
        }
        if (!is_array($data)) {
            exit(%d);
        }
        try {
            echo json_encode($data, JSON_THROW_ON_ERROR | JSON_PRESERVE_ZERO_FRACTION | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE);
        } catch (JsonException $notEncodable) {
            exit(%d);
        }
        PHP;

    public function __construct(
        private readonly ProcessFactory $processes,
    ) {}

    /**
     * @param string $file the absolute path of the file
     *
     * @return array<mixed> the array the file returns
     *
     * @throws DeploymentConfigUnreadable when the file is missing or unreadable, fails to evaluate, does
     *                                    not return an array, or returns values JSON cannot carry
     */
    public function load(string $file): array
    {
        if (!is_file($file) || !is_readable($file)) {
            throw new DeploymentConfigUnreadable(sprintf('%s does not exist or cannot be read.', $file));
        }

        $process = $this->processes->createWithInput(
            [
                PHP_BINARY,
                '-d', 'opcache.enable_cli=0',
                '-d', 'display_errors=stderr',
                '-d', 'auto_prepend_file=',
                '-d', 'auto_append_file=',
                '-d', 'serialize_precision=-1',
                '-r', sprintf(self::EVALUATOR, self::EXIT_NOT_AN_ARRAY, self::EXIT_NOT_ENCODABLE),
            ],
            dirname($file),
            null,
            $file,
            self::TIMEOUT_SECONDS,
        );
        try {
            $process->run();
        } catch (ProcessTimedOutException) {
            throw new DeploymentConfigUnreadable(sprintf('%s did not finish loading within %d seconds.', $file, (int) self::TIMEOUT_SECONDS));
        }

        $exitCode = $process->getExitCode();
        if ($exitCode === self::EXIT_NOT_AN_ARRAY) {
            throw new DeploymentConfigUnreadable(sprintf('%s does not return an array.', $file));
        }
        if ($exitCode === self::EXIT_NOT_ENCODABLE) {
            throw new DeploymentConfigUnreadable(sprintf(
                '%s returns a value that cannot be read back: a string that is not UTF-8, or a number that is not finite.',
                $file,
            ));
        }
        if ($exitCode !== 0) {
            throw new DeploymentConfigUnreadable(sprintf(
                'PHP failed to load %s (exit code %s); `php -l %s` shows whether it is a syntax error.',
                $file,
                $exitCode === null ? 'unknown' : (string) $exitCode,
                $file,
            ));
        }

        try {
            $data = json_decode($process->getOutput(), true, 512, JSON_THROW_ON_ERROR);
        } catch (\JsonException) {
            throw new DeploymentConfigUnreadable(sprintf('Loading %s printed something other than its array.', $file));
        }
        if (!is_array($data)) {
            throw new DeploymentConfigUnreadable(sprintf('%s does not return an array.', $file));
        }

        return $data;
    }
}
