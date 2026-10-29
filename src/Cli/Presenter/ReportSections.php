<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFinding;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\ReencryptionOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Cli\Output\TerminalText;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The parts several command results share, written the same way by every presenter: refusals, the
 * processes that may hold an earlier key ring, the web tier's answer, a scan's counts, what a
 * re-encryption wrote and left, the configuration cache clean and the next commands.
 *
 * Only counts, indices, fingerprints, paths and sentences of the use cases are written; the use cases
 * never put a value, a key or a password into them. Every string among them is printed as it is,
 * through {@see TerminalText}: a process's arguments, which any local user chooses, and the names of
 * tables and columns may carry a `<` or a control character, and neither may reach the terminal as a
 * style tag or an escape sequence.
 */
final class ReportSections
{
    public function __construct(
        private readonly TerminalText $text,
    ) {}

    /**
     * @param list<Refusal> $refusals
     */
    public function refusals(OutputInterface $output, array $refusals): void
    {
        if ($refusals === []) {
            return;
        }
        $output->writeln('<error>Refused:</error>');
        foreach ($refusals as $refusal) {
            $output->writeln(sprintf('  [%s] %s', $refusal->reason()->value, $this->escape($refusal->message())));
            $hint = $this->hint($refusal->reason());
            if ($hint !== null) {
                $output->writeln('    ' . $hint);
            }
        }
    }

    /**
     * @param list<RunningProcess> $workers
     */
    public function workers(OutputInterface $output, array $workers): void
    {
        if ($workers === []) {
            return;
        }
        $output->writeln('Processes that may hold an earlier key ring:');
        foreach ($workers as $worker) {
            $output->writeln(sprintf(
                '  %s (started %s)',
                $this->escape($worker->description()),
                $worker->startedAt()?->format(\DateTimeInterface::ATOM) ?? 'at an unknown time',
            ));
        }
    }

    public function probe(OutputInterface $output, ?ProbeOutcome $probe): void
    {
        if ($probe === null) {
            return;
        }
        $output->writeln(sprintf('Web tier: %s — %s', $probe->status()->value, $this->escape($probe->reason())));
    }

    /**
     * The scan's counts per key index, the columns it could not judge in full and the configuration
     * values it saw.
     */
    public function scan(OutputInterface $output, ScanReport $scan): void
    {
        $totals = $scan->toArray()['totals'];
        if ($totals === []) {
            $output->writeln('No encrypted values were found.');
        }
        foreach ($totals as $counts) {
            $index = $counts['index'];
            unset($counts['index']);
            $output->writeln(sprintf('  key index %d: %s', $index, $this->counts($counts)));
        }
        foreach ($scan->embeddedCandidates() as $candidate) {
            $output->writeln(sprintf('  %s: %d values hold a ciphertext inside a larger value (reported, never rewritten)', $this->escape($candidate->column()->toString()), $candidate->embeddedCount()));
        }
        foreach ($scan->incompleteColumns() as $candidate) {
            $output->writeln(sprintf('  %s: the database cut the scan short', $this->escape($candidate->column()->toString())));
        }
        foreach ($scan->columnsWithoutRowKey() as $candidate) {
            $output->writeln(sprintf('  %s: holds ciphertexts but its rows cannot be identified (no primary or unique key), so it is never rewritten', $this->escape($candidate->column()->toString())));
        }
        foreach ($scan->systemValues() as $finding) {
            $output->writeln(sprintf(
                '  %s %s: key index %d, %s',
                $finding->source() === SystemValueSource::Env ? 'app/etc/env.php' : 'app/etc/config.php',
                $this->escape($finding->value()->pathString()),
                $finding->keyIndex(),
                $finding->verdict()->value,
            ));
        }
    }

    public function reencryption(OutputInterface $output, string $title, ?ReencryptionOutcome $outcome): void
    {
        if ($outcome === null) {
            return;
        }
        $output->writeln(sprintf('%s: %d values rewritten in %d pass(es), %d left.', $this->escape($title), $outcome->appliedTotal(), $outcome->passes(), $outcome->remainingTotal()));
        foreach ($outcome->applied() as $column => $count) {
            $output->writeln(sprintf('  %s: %d rewritten', $this->escape($column), $count));
        }
        foreach ($outcome->skipped() as $column => $verdicts) {
            $output->writeln(sprintf('  %s: left alone: %s', $this->escape($column), $this->counts($verdicts)));
        }
        foreach ($outcome->conflicts() as $conflict) {
            $output->writeln(sprintf('  %s row %s: %s', $this->escape($conflict->column()->toString()), $this->escape($conflict->rowKey()->toJson()), $conflict->reason()->value));
        }
    }

    /**
     * The values of the committed configuration (`app/etc/config.php`) that decrypt under one of those
     * indices: the tool reads that file but never rewrites it, so they move only with a redeploy.
     *
     * @param list<int> $indices
     */
    public function committedOn(ScanReport $scan, array $indices): int
    {
        return count(array_filter(
            $scan->systemValues(SystemValueSource::Committed),
            static fn(SystemValueFinding $finding): bool => $finding->verdict()->isVerified() && in_array($finding->keyIndex(), $indices, true),
        ));
    }

    /**
     * @param list<string> $paths
     */
    public function systemPaths(OutputInterface $output, array $paths): void
    {
        if ($paths === []) {
            return;
        }
        $output->writeln(sprintf('app/etc/env.php values rewritten: %s', $this->escape(implode(', ', $paths))));
    }

    public function cacheClean(OutputInterface $output, ?CacheCleanOutcome $clean): void
    {
        if ($clean === null) {
            return;
        }
        $output->writeln(sprintf(
            'Configuration cache: %s',
            $clean->cleaned() ? 'cleaned' : '<comment>not cleaned</comment> — ' . $this->escape($clean->reason()),
        ));
    }

    /**
     * @param list<string> $commands each a full command line followed by what it does
     */
    public function nextCommands(OutputInterface $output, array $commands): void
    {
        if ($commands === []) {
            return;
        }
        $output->writeln('Next:');
        foreach ($commands as $command) {
            $output->writeln('  ' . $this->escape($command));
        }
    }

    /**
     * Text from the use cases, printed as it is: a `<` in a path or a message is not a style tag, and a
     * control character is shown as its `\xNN` escape.
     */
    public function escape(string $text): string
    {
        return $this->text->literal($text);
    }

    /**
     * @param array<string, int> $counts
     */
    private function counts(array $counts): string
    {
        $parts = [];
        foreach ($counts as $name => $count) {
            if ($count !== 0) {
                $parts[] = sprintf('%d %s', $count, $this->escape(str_replace('_', ' ', $name)));
            }
        }

        return $parts === [] ? 'nothing' : implode(', ', $parts);
    }

    /**
     * What the operator does about a refusal whose way out is not obvious from its sentence alone.
     */
    private function hint(RefusalReason $reason): ?string
    {
        return match ($reason) {
            RefusalReason::CommittedValuesOnRemovedKey => 'Redeploy app/etc/config.php with those values encrypted under the key that was active before the run, then run rollback again.',
            RefusalReason::RollbackInProgress => 'Run rollback again; until it finishes, rotate, retire and purge refuse.',
            RefusalReason::WorkersRunning => 'Stop cron and the queue consumers for the few minutes of the command, or pass --ignore-workers (recorded in the run).',
            default => null,
        };
    }
}
