<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Output;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Symfony\Component\Console\Output\ConsoleOutputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Tells the operator what the running use case does, on the error output, so the standard output holds
 * only the command's result (a JSON report stays parseable). Steps and warnings always show; the values
 * handled per column show with `-v`.
 *
 * A message is printed as it is: it may quote a process's arguments, which any local user chooses, or
 * a table name, so a `<` in it is never read as a style tag and no control character in it reaches the
 * terminal ({@see TerminalText}).
 *
 * The output is the running command's, set when the command starts ({@see
 * \Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContextListener}); a use case reporting progress
 * before then is a programming error and fails loudly.
 */
final class ConsoleProgress implements Progress
{
    private ?OutputInterface $output = null;

    public function __construct(
        private readonly TerminalText $text,
    ) {}

    public function useOutput(OutputInterface $output): void
    {
        $this->output = $output instanceof ConsoleOutputInterface ? $output->getErrorOutput() : $output;
    }

    public function step(string $message): void
    {
        $this->output()->writeln('<info>›</info> ' . $this->text->literal($message));
    }

    public function advance(ColumnRef $column, int $count): void
    {
        $this->output()->writeln(sprintf('    %s: %d more', $this->text->literal($column->toString()), $count), OutputInterface::VERBOSITY_VERBOSE);
    }

    public function warn(string $message): void
    {
        $this->output()->writeln('<comment>Warning:</comment> ' . $this->text->literal($message));
    }

    /**
     * @throws \LogicException when no command has started
     */
    private function output(): OutputInterface
    {
        return $this->output ?? throw new \LogicException('Progress was reported before a command started; there is no output to write it to.');
    }
}
