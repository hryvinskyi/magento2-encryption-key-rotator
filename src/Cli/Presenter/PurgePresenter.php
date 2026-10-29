<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Purge\PurgeStatus;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes what a purge did and gives its exit code. A loss the operator accepted is written with its
 * counts, so the output records what became unreadable for good.
 */
final class PurgePresenter
{
    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    public function present(PurgeResult $result, OutputInterface $output): int
    {
        $output->writeln(sprintf('Purge: <info>%s</info>', $result->status()->value));
        $this->sections->refusals($output, $result->refusals());
        if ($result->purgedIndices() !== []) {
            $output->writeln(sprintf(
                'Key indices made unreadable for good: %s; %d value(s) there still decrypt with a kept key, %d sit in columns without a row key, %d embedded value(s) and %d cut-short column(s) could not be judged.',
                implode(', ', $result->purgedIndices()),
                $result->stillReadable(),
                $result->withoutRowKey(),
                $result->embedded(),
                $result->incompleteColumns(),
            ));
        }
        if ($result->acceptedLoss()) {
            $output->writeln(sprintf(
                '<comment>Loss accepted (--accept-loss):</comment> %d value(s) that still decrypted, %d value(s) in columns without a row key and %d embedded value(s) are now unreadable for good.',
                $result->stillReadable(),
                $result->withoutRowKey(),
                $result->embedded(),
            ));
        }
        if ($result->status() === PurgeStatus::Purged) {
            $output->writeln(sprintf(
                'Deleted %d journal entr%s; run directory %s.',
                $result->journalEntriesDeleted(),
                $result->journalEntriesDeleted() === 1 ? 'y' : 'ies',
                $result->runDirectoryRemoved() ? 'removed with its kept keys' : 'not removed',
            ));
        }
        $runId = $result->runId()?->toString();
        $output->writeln($runId === null ? 'No run to purge.' : sprintf('Run: <info>%s</info> (%s)', $runId, $result->state()->value ?? 'gone'));

        return match ($result->status()) {
            PurgeStatus::Purged, PurgeStatus::NothingToPurge => ExitCode::DONE,
            PurgeStatus::Refused => ExitCode::REFUSED,
        };
    }
}
