<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateKey;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RotatePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Rotate\KeyFile;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Appends a new key and moves every value under the previous keys onto it, or resumes the active run.
 */
#[AsCommand(name: 'rotate', description: 'Append a new key and re-encrypt every value under the old keys (resumes an unfinished run)')]
final class RotateCommand extends Command
{
    private const DRY_RUN = 'dry-run';
    private const KEY_FILE = 'key-file';

    public function __construct(
        private readonly RotateKey $rotation,
        private readonly ReportStatus $status,
        private readonly RotateRequestFactory $requests,
        private readonly ProbeSettingsProvider $probeSettings,
        private readonly KeyFile $keyFile,
        private readonly Confirmation $confirmation,
        private readonly RotatePresenter $presenter,
        private readonly StatusPresenter $statusPresenter,
        private readonly CommandOptions $options,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->options->addStoreOptions($this);
        $this->options->addProbeOptions($this);
        $this->options->addBatchSizeOption($this);
        $this->options->addIgnoreWorkersOption($this);
        $this->options->addConfirmationOption($this);
        $this
            ->addOption(self::DRY_RUN, null, InputOption::VALUE_NONE, 'Scan and print the plan; write nothing')
            ->addOption(self::KEY_FILE, null, InputOption::VALUE_REQUIRED, 'Append the key in this file (its ring entry, mode 0600) instead of a random one');
        $this->setHelp(<<<'HELP'
            Appends a new key to the ring in app/etc/env.php, waits until the web tier (PHP-FPM) holds the new ring,
            then re-encrypts every value under the old usable keys, in the database and in app/etc/env.php, and cleans
            the configuration cache. Running it again resumes an unfinished run where it stands.

            The web tier is confirmed through --probe-fcgi (FastCGI to the PHP-FPM socket), --probe-url (HTTP, where the
            web server runs any .php file) or skipped with --skip-web-probe; one of them is required.

            Every column of the database is covered: unlike scan, rotate takes no --exclude, so retire and rollback never
            meet a column the rotation skipped.

            A key is never taken from the command line, where the process list and the shell history would show it:
            --key-file names a file readable by its owner only.

            Exit codes: 0 done, 2 waiting for the web tier (run the command again once PHP-FPM reloaded),
            3 refused (nothing was written past the check), 1 unexpected error.
            HELP);
    }

    /**
     * @throws OptionRefused when an option cannot be used
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $dryRun = $input->getOption(self::DRY_RUN) === true;
        $settings = $this->probeSettings->settings();
        if (!$dryRun) {
            $this->options->requireProbeChoice($settings);
        }
        $keyFile = $input->getOption(self::KEY_FILE);
        $rawKey = is_string($keyFile) && $keyFile !== '' ? $this->keyFile->read($keyFile) : null;

        $request = $this->request($input, $dryRun, $rawKey);
        if (!$dryRun && $this->confirmation->mustAsk($input)) {
            $stop = $this->confirm($input, $output, $rawKey);
            if ($stop !== null) {
                return $stop;
            }
        }

        return $this->presenter->present(
            $this->rotation->rotate($request),
            $output,
            $this->options->repeated($input, false),
            $this->options->repeated($input, true),
        );
    }

    /**
     * Shows what the rotation will do and asks: the run id of a run it resumes, the start word for a new
     * one, whose plan comes from a dry run.
     *
     * @return int|null the exit code to stop with, or null to go on
     */
    private function confirm(InputInterface $input, OutputInterface $output, #[\SensitiveParameter] ?string $rawKey): ?int
    {
        $status = $this->status->status();
        $runId = $status->runId();
        if ($status->isActive() && $runId !== null) {
            $this->statusPresenter->plan($status, $output, 'resume');

            return $this->confirmation->ask($input, $output, $runId) ? null : $this->notConfirmed($output);
        }

        $plan = $this->rotation->rotate($this->request($input, true, $rawKey));
        $this->presenter->plan($plan, $output);
        if ($plan->refusals() !== []) {
            $output->writeln('The rotation would be refused; nothing was written.');

            return ExitCode::REFUSED;
        }

        return $this->confirmation->ask($input, $output, Confirmation::START_WORD) ? null : $this->notConfirmed($output);
    }

    /**
     * @throws OptionRefused when an option cannot be used
     */
    private function request(InputInterface $input, bool $dryRun, #[\SensitiveParameter] ?string $rawKey): RotateRequest
    {
        try {
            return $this->requests->create(
                dryRun: $dryRun,
                rawKey: $rawKey,
                batchSize: $this->options->batchSize($input),
                ignoreWorkers: $this->options->ignoresWorkers($input),
                allowOtherUser: $this->options->allowsOtherUser($input),
                probeSettings: $this->probeSettings->settings(),
            );
        } catch (InvalidValue $invalid) {
            throw new OptionRefused($invalid->getMessage(), 0, $invalid);
        }
    }

    private function notConfirmed(OutputInterface $output): int
    {
        $output->writeln('Not confirmed; nothing was written.');

        return ExitCode::REFUSED;
    }
}
