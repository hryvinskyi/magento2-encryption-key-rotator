<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\ProbeSettingsProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireOldKeys;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireRequestFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\ReportStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\Confirmation\Confirmation;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\RetirePresenter;
use Hryvinskyi\EncryptionKeyRotator\Cli\Presenter\StatusPresenter;
use Symfony\Component\Console\Attribute\AsCommand;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Input\InputOption;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Replaces the keys a rotation moved away from by placeholders, once no stored value needs them.
 */
#[AsCommand(name: 'retire', description: 'Replace the old keys of a re-encrypted run by placeholders')]
final class RetireCommand extends Command
{
    private const ACCEPT_EMBEDDED = 'accept-embedded';
    private const CACHE_CLEANED_MANUALLY = 'cache-cleaned-manually';

    public function __construct(
        private readonly RetireOldKeys $retirement,
        private readonly ReportStatus $status,
        private readonly RetireRequestFactory $requests,
        private readonly ProbeSettingsProvider $probeSettings,
        private readonly Confirmation $confirmation,
        private readonly RetirePresenter $presenter,
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
        $this
            ->addOption(self::ACCEPT_EMBEDDED, null, InputOption::VALUE_NONE, 'Retire although values hold a ciphertext inside a larger value, or a column scan was cut short (recorded in the run); never waives a whole value left on an old key')
            ->addOption(self::CACHE_CLEANED_MANUALLY, null, InputOption::VALUE_NONE, 'The configuration cache was cleaned by hand after the last re-encryption (recorded in the run)');
        $this->setHelp(<<<'HELP'
            Moves stragglers written under the old keys since the rotation, then replaces the old keys by placeholders
            in app/etc/env.php, once no value in the database, app/etc/env.php or app/etc/config.php needs them, and
            waits until the web tier holds the new ring. The run directory keeps the replaced keys until purge.

            --accept-embedded waives only values that hold a ciphertext inside a larger value and columns whose scan was
            cut short. A whole value left on an old key is never waived by it, wherever it sits: in the database, in a
            table without a row key (which the tool cannot rewrite: give the table a key or move the value by hand), in
            app/etc/env.php or in app/etc/config.php. --cache-cleaned-manually waives only the configuration cache clean.

            Exit codes: 0 done, 2 waiting for the web tier, 3 refused, 1 unexpected error.
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
            acceptEmbedded: $input->getOption(self::ACCEPT_EMBEDDED) === true,
            cacheCleanedManually: $input->getOption(self::CACHE_CLEANED_MANUALLY) === true,
            ignoreWorkers: $this->options->ignoresWorkers($input),
            allowOtherUser: $this->options->allowsOtherUser($input),
            probeSettings: $settings,
        );

        if ($this->confirmation->mustAsk($input)) {
            $status = $this->status->status();
            $runId = $status->runId();
            if ($status->isActive() && $runId !== null) {
                $this->statusPresenter->plan($status, $output, 'replace the old keys by placeholders for');
                if (!$this->confirmation->ask($input, $output, $runId)) {
                    $output->writeln('Not confirmed; nothing was written.');

                    return ExitCode::REFUSED;
                }
            }
        }

        return $this->presenter->present(
            $this->retirement->retire($request),
            $output,
            $this->options->repeated($input, false),
            $this->options->repeated($input, true),
        );
    }
}
