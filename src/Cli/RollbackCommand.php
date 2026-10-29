<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackRotation;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RollBackPresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Undoes the active rotation, from any state before it is purged; safe to run again after a crash.
 */
#[AsCommand(name: 'rollback', description: 'Undo the unfinished or retired run and restore the key ring from before it')]
final class RollbackCommand extends Command
{
    private const ACCEPT_EMBEDDED = 'accept-embedded';

    public function __construct(
        private readonly RollBackRotation $rollback,
        private readonly ReportStatus $status,
        private readonly RollBackRequestFactory $requests,
        private readonly ProbeSettingsProvider $probeSettings,
        private readonly Confirmation $confirmation,
        private readonly RollBackPresenter $presenter,
        private readonly StatusPresenter $statusPresenter,
        private readonly CommandOptions $options,
    ) {
        parent::__construct();
    }

    protected function configure(): void
    {
        $this->options->addStoreOptions($this);
        $this->options->addProbeOptions($this);
        $this->options->addIgnoreWorkersOption($this);
        $this->options->addConfirmationOption($this);
        $this->addOption(self::ACCEPT_EMBEDDED, null, InputOption::VALUE_NONE, 'Remove the new key although values hold a ciphertext inside a larger value, or a column scan was cut short (recorded in the run)');
        $this->setHelp(<<<'HELP'
            Restores the slots the run retired, gives every value its bytes from before the run back (or moves values
            the store wrote under the new key onto the key active before the run), removes the new slot, and waits until
            the web tier holds the ring from before the run. Interrupted, it is finished by running it again; while it
            is in progress, rotate, retire and purge refuse.

            Before the new key is removed the store is scanned again, and the rollback refuses while anything still needs
            that key: a value under it in the database or app/etc/env.php that could not be moved back, a value under it
            in a table without a row key (which the tool cannot rewrite), or a value under it in the deployed
            app/etc/config.php (redeploy the file with the values encrypted under the earlier key). Move them, then run
            rollback again; the run stays in progress meanwhile.

            --accept-embedded waives only values that hold a ciphertext inside a larger value and columns whose scan was
            cut short; it never waives a whole value under the new key. Store processes still running at the moment the
            new key is removed refuse it too, whenever they started: --ignore-workers waives that.

            Exit codes: 0 done (or already rolled back), 2 waiting for the web tier, 3 refused, 1 unexpected error.
            HELP);
    }

    /**
     * @throws OptionRefused when an option cannot be used
     */
    protected function execute(InputInterface $input, OutputInterface $output): int
    {
        $settings = $this->probeSettings->settings();
        $this->options->requireProbeChoice($settings);
        $request = $this->requests->create(
            ignoreWorkers: $this->options->ignoresWorkers($input),
            allowOtherUser: $this->options->allowsOtherUser($input),
            probeSettings: $settings,
            acceptEmbedded: $input->getOption(self::ACCEPT_EMBEDDED) === true,
        );

        if ($this->confirmation->mustAsk($input)) {
            $status = $this->status->status();
            $runId = $status->runId();
            if ($status->isActive() && $runId !== null) {
                $this->statusPresenter->plan($status, $output, 'roll back');
                if (!$this->confirmation->ask($input, $output, $runId)) {
                    $output->writeln('Not confirmed; nothing was written.');

                    return ExitCode::REFUSED;
                }
            }
        }

        return $this->presenter->present(
            $this->rollback->rollBack($request),
            $output,
            $this->options->repeated($input, false),
            $this->options->repeated($input, true),
        );
    }
}
