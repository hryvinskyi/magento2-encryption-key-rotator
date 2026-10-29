<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback\RollBackStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes what a rollback did and gives its exit code.
 */
final class RollBackPresenter
{
    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    /**
     * @param string $storeOptions the store options to repeat in the next commands
     * @param string $probeOptions the store and probe options to repeat in the next commands
     */
    public function present(RollBackResult $result, OutputInterface $output, string $storeOptions, string $probeOptions): int
    {
        $output->writeln(sprintf(
            'Rollback: <info>%s</info>%s',
            $result->status()->value,
            $result->rolledBackFrom() === null ? '' : sprintf(' (from %s)', $result->rolledBackFrom()->value),
        ));
        $this->sections->refusals($output, $result->refusals());
        $this->sections->workers($output, $result->workers());
        $this->sections->probe($output, $result->probe());
        $journal = $result->journal();
        if ($journal !== null) {
            $output->writeln(sprintf(
                'Journal: %d value(s) given their bytes from before the run back, %d rewritten by the store meanwhile moved onto the earlier key, %d left alone.',
                $journal->reverted(),
                $journal->superseded(),
                count($journal->leftAlone()),
            ));
            foreach ($journal->leftAlone() as $conflict) {
                $output->writeln(sprintf('  %s row %s: %s', $this->sections->escape($conflict->column()->toString()), $this->sections->escape($conflict->rowKey()->toJson()), $conflict->reason()->value));
            }
        }
        $this->sections->reencryption($output, 'Values the store wrote under the new key, moved back', $result->storeWritten());
        $this->sections->reencryption($output, 'Stragglers moved back after the new slot was removed', $result->stragglers());
        $this->sections->systemPaths($output, $result->rewrittenSystemPaths());
        $this->sections->cacheClean($output, $result->cacheClean());
        if ($result->scan() !== null) {
            $output->writeln('Values per key index now:');
            $this->sections->scan($output, $result->scan());
        }
        if ($result->bearerTokenNote() !== null) {
            $output->writeln('Note: ' . $result->bearerTokenNote());
        }

        $runId = $result->runId()?->toString();
        $output->writeln('');
        $output->writeln($runId === null ? 'No run was found.' : sprintf('Run: <info>%s</info> (%s)', $runId, $result->state()->value ?? 'unknown state'));
        $next = [sprintf('key-rotator status %s', $storeOptions)];
        $done = $result->status() === RollBackStatus::RolledBack || $result->status() === RollBackStatus::AlreadyRolledBack;
        $next[] = $done
            ? sprintf('key-rotator purge %s   destroys the kept keys and the journal of the rolled-back run', $storeOptions)
            : sprintf('key-rotator rollback %s   continues the rollback once the cause above is resolved (reload PHP-FPM when the web tier waits)', $probeOptions);
        $this->sections->nextCommands($output, $next);

        return match ($result->status()) {
            RollBackStatus::RolledBack, RollBackStatus::AlreadyRolledBack => ExitCode::DONE,
            RollBackStatus::AwaitingWebTier => ExitCode::WAITING,
            RollBackStatus::Refused => ExitCode::REFUSED,
        };
    }
}
