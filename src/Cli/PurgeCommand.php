<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\PurgePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidRunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Destroys what a retired or rolled-back run kept to undo itself: its journal and its run directory.
 */
#[AsCommand(name: 'purge', description: 'Delete the journal and the kept keys of a retired or rolled-back run')]
final class PurgeCommand extends Command
{
    private const ACCEPT_LOSS = 'accept-loss';
    private const RUN_ID = 'run-id';

    public function __construct(
        private readonly PurgeRotation $purge,
        private readonly ReportStatus $status,
        private readonly PurgeRequestFactory $requests,
        private readonly RunIdFactory $runIds,
        private readonly Confirmation $confirmation,
        private readonly PurgePresenter $presenter,
        private readonly StatusPresenter $statusPresenter,
        private readonly CommandOptions $options,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->options->addStoreOptions($this);
        $this->options->addConfirmationOption($this);
        $this
            ->addOption(self::RUN_ID, null, InputOption::VALUE_REQUIRED, 'The run to purge; the current or last run by default')
            ->addOption(self::ACCEPT_LOSS, null, InputOption::VALUE_NONE, 'Purge although values would become unreadable: values only the kept keys decrypt, values in tables without a row key, embedded values and cut-short columns (recorded and printed with the counts)');
        $this->setHelp(<<<'HELP'
            After a purge the run can no longer be rolled back: its kept keys and its journal of old values are gone.
            The purge first checks, with the kept keys, that no value still needs them, and refuses while any does,
            unless --accept-loss. --accept-loss waives, each counted on its own: values on the purged key indices that
            still decrypt only with a kept key, values on them in tables without a row key (which the scan cannot
            verify), values that hold a ciphertext inside a larger value, and columns whose scan was cut short.

            Exit codes: 0 done (or nothing to purge), 3 refused, 1 unexpected error.
            HELP);
    }

    /**
     * @throws OptionRefused when an option cannot be used
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $runId = $this->runId($input);
        $request = $this->requests->create(runId: $runId, acceptLoss: $input->getOption(self::ACCEPT_LOSS) === true);

        if ($this->confirmation->mustAsk($input)) {
            $status = $this->status->status();
            $target = $runId?->toString() ?? $status->runId();
            if ($target !== null) {
                if ($runId === null) {
                    $this->statusPresenter->plan($status, $output, 'destroy the journal and the kept keys of');
                }
                if (!$this->confirmation->ask($input, $output, $target)) {
                    $output->writeln('Not confirmed; nothing was deleted.');

                    return ExitCode::REFUSED;
                }
            }
        }

        return $this->presenter->present($this->purge->purge($request), $output);
    }

    /**
     * @throws OptionRefused when the run id is malformed
     */
    private function runId(InputInterface $input): ?RunId
    {
        $given = $input->getOption(self::RUN_ID);
        if (!is_string($given) || $given === '') {
            return null;
        }
        try {
            return $this->runIds->create($given);
        } catch (InvalidRunId $invalid) {
            throw new OptionRefused(sprintf('--%s: %s', self::RUN_ID, $invalid->getMessage()), 0, $invalid);
        }
    }
}
