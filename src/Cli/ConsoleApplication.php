<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Package\PackageVersion;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunLocked;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\SecretRedactor;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\UnusableStateDirectory;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;
use Symfony\Contracts\EventDispatcher\EventDispatcherInterface;

/**
 * The console application: every registered command, and the event dispatcher through which Console
 * announces each command before it runs.
 *
 * It owns the exit code of everything a command throws. Options that cannot be used, another process
 * holding the run store, a run store holding more than one unfinished run and a state directory that
 * cannot be used safely are refusals (exit 3): nothing was written past them. Anything else is an
 * unexpected error (exit 1), whatever code the exception carries, so it can never pass for "waiting" or
 * "refused". Either is written as one line on the error output, passed through the secret redactor
 * first since an error may quote a stored value, a key or a password, then through {@see TerminalText},
 * since it may quote a path or the arguments of another user's process; `-vvv` adds where it was thrown
 * and the trace, without arguments.
 */
final class ConsoleApplication extends Application
{
    public const NAME = 'key-rotator';

    /**
     * @param iterable<Command> $commands
     */
    public function __construct(
        iterable $commands,
        EventDispatcherInterface $dispatcher,
        PackageVersion $version,
        private readonly SecretRedactor $redactor,
        private readonly TerminalText $text,
    ) {
        parent::__construct(self::NAME, $version->version());
        $this->setDispatcher($dispatcher);
        foreach ($commands as $command) {
            $this->add($command);
        }
    }

    public function doRun(InputInterface $input, OutputInterface $output): int
    {
        try {
            return parent::doRun($input, $output);
        } catch (OptionRefused|RunLocked|ConflictingRuns|UnusableStateDirectory $refused) {
            $this->errorOutput($output)->writeln('<error>Refused:</error> ' . $this->line($refused));

            return ExitCode::REFUSED;
        } catch (\Throwable $failure) {
            $this->renderThrowable($failure, $this->errorOutput($output));

            return ExitCode::UNEXPECTED;
        }
    }

    public function renderThrowable(\Throwable $e, OutputInterface $output): void
    {
        $output->writeln(sprintf('<error>Error:</error> %s', $this->line($e)));
        if ($output->getVerbosity() < OutputInterface::VERBOSITY_DEBUG) {
            return;
        }
        $output->writeln($this->text->literal(sprintf('%s thrown in %s:%d', $e::class, $e->getFile(), $e->getLine())));
        foreach (explode("\n", $this->redactor->redact($e->getTraceAsString())) as $frame) {
            $output->writeln($this->text->literal($frame));
        }
    }

    private function line(\Throwable $e): string
    {
        $message = $e->getMessage() === '' ? $e::class : $e->getMessage();

        return $this->text->literal($this->redactor->redact($message));
    }

    private function errorOutput(OutputInterface $output): OutputInterface
    {
        return $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }
}
