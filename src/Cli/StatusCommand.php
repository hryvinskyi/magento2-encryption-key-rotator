<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Shows the store's current or last run and the commands it allows next, read-only.
 */
#[AsCommand(name: 'status', description: 'Show the current or last run and what it allows next (read-only)')]
final class StatusCommand extends Command
{
    private const FORMAT = 'format';

    public function __construct(
        private readonly ReportStatus $status,
        private readonly StatusPresenter $presenter,
        private readonly CommandOptions $options,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->options->addStoreOptions($this);
        $this->addOption(self::FORMAT, null, InputOption::VALUE_REQUIRED, 'table or json', 'table');
        $this->setHelp(<<<'HELP'
            Reads the state directory only. <info>--format=json</info> writes one JSON object: run_id, state, active,
            rolled_back_from, started_at, ring_fingerprint_before, ring_fingerprint, intended_ring_fingerprint,
            source_indices, new_index, last_ring_write_at, probe_skipped, config_cache_cleaned, last_scan, overrides,
            history and next_commands. run_id and state are null when the store has no run.
            HELP);
    }

    /**
     * @throws OptionRefused when the format is unknown
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $format = $input->getOption(self::FORMAT);
        if ($format !== 'table' && $format !== 'json') {
            throw new OptionRefused(sprintf('--%s is table or json.', self::FORMAT));
        }
        $report = $this->status->status();

        if ($format === 'json') {
            $this->presenter->json($report, $output);

            return ExitCode::DONE;
        }
        $this->presenter->text($report, $output, $this->options->repeated($input, false));

        return ExitCode::DONE;
    }
}
