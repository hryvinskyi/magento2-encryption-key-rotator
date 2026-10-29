<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Retire\RetireStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes what retiring the old keys did and gives its exit code.
 */
final class RetirePresenter
{
    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    /**
     * @param string $storeOptions the store options to repeat in the next commands
     * @param string $probeOptions the store and probe options to repeat in the next commands
     */
    public function present(RetireResult $result, OutputInterface $output, string $storeOptions, string $probeOptions): int
    {
        $output->writeln(sprintf('Retirement: <info>%s</info>', $result->status()->value));
        $this->sections->refusals($output, $result->refusals());
        $this->sections->workers($output, $result->workers());
        $this->sections->probe($output, $result->probe());
        $this->sections->reencryption($output, 'Stragglers moved before the key ring write', $result->stragglersBeforeWrite());
        $this->sections->reencryption($output, 'Stragglers moved after the key ring write', $result->stragglersAfterWrite());
        $this->sections->systemPaths($output, $result->rewrittenSystemPaths());
        $this->sections->cacheClean($output, $result->cacheClean());
        if ($result->retiredIndices() !== []) {
            $output->writeln(sprintf('Retired key indices: %s (replaced by placeholders; the run directory keeps the keys until purge)', implode(', ', $result->retiredIndices())));
        }
        if ($result->scan() !== null) {
            $output->writeln('Values per key index now:');
            $this->sections->scan($output, $result->scan());
        }

        $runId = $result->runId()?->toString();
        $output->writeln('');
        $output->writeln($runId === null ? 'No run was found.' : sprintf('Run: <info>%s</info> (%s)', $runId, $result->state()->value ?? 'unknown state'));
        $next = [sprintf('key-rotator status %s', $storeOptions)];
        if ($result->status() !== RetireStatus::Retired) {
            $next[] = sprintf('key-rotator retire %s   once the cause above is resolved (reload PHP-FPM when the web tier waits)', $probeOptions);
        }
        if ($result->status() === RetireStatus::Retired) {
            $next[] = sprintf('key-rotator purge %s   destroys the kept keys and the journal; the run cannot be rolled back after it', $storeOptions);
        }
        if ($runId !== null) {
            $next[] = sprintf('key-rotator rollback %s   undoes run %s', $probeOptions, $runId);
        }
        $this->sections->nextCommands($output, $next);

        return match ($result->status()) {
            RetireStatus::Retired => ExitCode::DONE,
            RetireStatus::AwaitingWebTier => ExitCode::WAITING,
            RetireStatus::Refused => ExitCode::REFUSED,
        };
    }
}
