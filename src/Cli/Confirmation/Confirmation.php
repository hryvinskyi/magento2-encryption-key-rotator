<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation;

use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\OptionRefused;
use Symfony\Component\Console\Exception\MissingInputException;
use Symfony\Component\Console\Helper\QuestionHelper;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Asks the operator to confirm a command that writes, by typing a given word: the run id when the
 * command acts on a run, `YES` when it starts one. `--yes` confirms up front. Without a terminal to ask
 * on (`--no-interaction`) and without `--yes` the command is refused, never confirmed by default.
 */
final class Confirmation
{
    public const START_WORD = 'YES';

    public function __construct(
        private readonly QuestionHelper $questions,
        private readonly QuestionFactory $questionFactory,
        private readonly CommandOptions $options,
    ) {}

    /**
     * Whether the command has to ask before it writes: false when it was confirmed up front.
     *
     * @throws OptionRefused when the command would have to ask but cannot
     */
    public function mustAsk(InputInterface $input): bool
    {
        if ($this->options->confirmedUpFront($input)) {
            return false;
        }
        if (!$input->isInteractive()) {
            throw new OptionRefused(sprintf('This command writes and asks for confirmation; without interaction, pass --%s. Nothing was written.', CommandOptions::YES));
        }

        return true;
    }

    /**
     * Whether the operator typed the expected word; an input that ends before an answer (a closed
     * standard input) is no confirmation.
     *
     * @param string $expected the word the operator must type: a run id, or {@see START_WORD}
     */
    public function ask(InputInterface $input, OutputInterface $output, string $expected): bool
    {
        try {
            $answer = $this->questions->ask($input, $output, $this->questionFactory->create(sprintf(
                $expected === self::START_WORD ? 'Type %s to continue: ' : 'Type the run id %s to continue: ',
                $expected,
            )));
        } catch (MissingInputException) {
            return false;
        }

        return is_string($answer) && trim($answer) === $expected;
    }
}
