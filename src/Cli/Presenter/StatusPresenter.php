<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\RunCommand;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status\StatusReport;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes where the run of a store stands, as text or as JSON, with the commands it allows next.
 *
 * The JSON is an object with `run_id`, `state`, `active`, `rolled_back_from`, `started_at`,
 * `ring_fingerprint_before`, `ring_fingerprint`, `intended_ring_fingerprint`,
 * `deployment_ring_fingerprint` (the ring `env.php` holds now), `deployment_ring_differs`, `source_indices`,
 * `new_index`, `last_ring_write_at`, `probe_skipped`, `config_cache_cleaned`, `last_scan` (verified
 * values per index, undecryptable, embedded, incomplete columns), `overrides`, `history` and
 * `next_commands`; `run_id` and `state` are null when the store has no run.
 */
final class StatusPresenter
{
    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    /**
     * @param string $storeOptions the store options to repeat in the next commands
     */
    public function text(StatusReport $report, OutputInterface $output, string $storeOptions): void
    {
        $state = $report->state();
        if (!$report->hasRun() || $state === null) {
            $output->writeln('No run: the state directory holds no rotation of this store.');
            $this->next($report, $output, $storeOptions);

            return;
        }

        $output->writeln(sprintf('Run: <info>%s</info>', (string) $report->runId()));
        $output->writeln(sprintf('State: <info>%s</info>%s', $state->value, $report->rolledBackFrom() === null ? '' : sprintf(' (from %s)', $report->rolledBackFrom()->value)));
        if ($state === RunState::RollingBack) {
            $output->writeln('<comment>Rollback in progress: run rollback again.</comment> Until it finishes, rotate, retire and purge refuse.');
        }
        if ($this->holdsNewKey($state)) {
            $output->writeln('Do not restore the env.php.bak of the run directory by hand: every value already moved onto the new key would become unreadable. Rollback is the way back.');
        }
        $output->writeln(sprintf('Started: %s', $report->startedAt()?->format(\DateTimeInterface::ATOM) ?? 'unknown'));
        $output->writeln(sprintf('Key ring before the run: %s', $report->ringFingerprintBefore() ?? 'unknown'));
        $output->writeln(sprintf('Key ring the run recorded: %s', $report->ringFingerprint() ?? 'unknown'));
        if ($report->intendedRingFingerprint() !== null) {
            $output->writeln(sprintf('Key ring write announced: %s', $report->intendedRingFingerprint()));
        }
        $output->writeln(sprintf('Key ring in env.php now: %s', $report->deploymentRingFingerprint() ?? 'none usable'));
        if ($report->deploymentRingDiffers()) {
            $output->writeln('<comment>env.php holds neither the key ring the run recorded nor the one it announced.</comment> A deploy or another writer replaced it; every command of the run refuses until the env.php the run wrote is back.');
        }
        $output->writeln(sprintf(
            'Moves key indices %s onto %s',
            implode(', ', $report->sourceIndices()),
            $report->newIndex() === null ? '?' : (string) $report->newIndex(),
        ));
        $output->writeln(sprintf('Last key ring write: %s', $report->lastRingWriteAt()?->format(\DateTimeInterface::ATOM) ?? 'none'));
        $output->writeln(sprintf('Web probe skipped: %s; configuration cache cleaned: %s', $report->probeSkipped() ? 'yes' : 'no', $report->configCacheCleaned() ? 'yes' : 'no'));

        $summary = $report->lastSummary();
        if ($summary !== null) {
            $verified = [];
            foreach ($summary->verifiedPerIndex() as $index => $count) {
                $verified[] = sprintf('%d under index %d', $count, $index);
            }
            $withoutRowKey = [];
            foreach ($summary->withoutRowKeyPerIndex() as $index => $count) {
                $withoutRowKey[] = sprintf('%d under index %d', $count, $index);
            }
            $output->writeln(sprintf(
                'Last scan: %s; %d undecryptable, %d embedded, %d column(s) cut short%s',
                $verified === [] ? 'no verified values' : implode(', ', $verified),
                $summary->undecryptable(),
                $summary->embedded(),
                $summary->incompleteColumns(),
                $withoutRowKey === [] ? '' : sprintf('; in columns without a row key: %s', implode(', ', $withoutRowKey)),
            ));
        }
        foreach ($report->overrides() as $override) {
            $output->writeln(sprintf('Override: %s (at %s, %s)', $override['override']->value, $override['state']->value, $override['at']->format(\DateTimeInterface::ATOM)));
        }
        $output->writeln('History:', OutputInterface::VERBOSITY_VERBOSE);
        foreach ($report->history() as $entry) {
            $output->writeln(sprintf('  %s %s', $entry['at']->format(\DateTimeInterface::ATOM), $entry['state']->value), OutputInterface::VERBOSITY_VERBOSE);
        }
        $this->next($report, $output, $storeOptions);
    }

    public function json(StatusReport $report, OutputInterface $output): void
    {
        $summary = $report->lastSummary();
        $output->writeln(json_encode([
            'run_id' => $report->runId(),
            'state' => $report->state()?->value,
            'active' => $report->isActive(),
            'rolled_back_from' => $report->rolledBackFrom()?->value,
            'started_at' => $report->startedAt()?->format(\DateTimeInterface::ATOM),
            'ring_fingerprint_before' => $report->ringFingerprintBefore(),
            'ring_fingerprint' => $report->ringFingerprint(),
            'intended_ring_fingerprint' => $report->intendedRingFingerprint(),
            'deployment_ring_fingerprint' => $report->deploymentRingFingerprint(),
            'deployment_ring_differs' => $report->deploymentRingDiffers(),
            'source_indices' => $report->sourceIndices(),
            'new_index' => $report->newIndex(),
            'last_ring_write_at' => $report->lastRingWriteAt()?->format(\DateTimeInterface::ATOM),
            'probe_skipped' => $report->probeSkipped(),
            'config_cache_cleaned' => $report->configCacheCleaned(),
            'last_scan' => $summary?->snapshot(),
            'overrides' => array_map(static fn(array $override): array => [
                'override' => $override['override']->value,
                'state' => $override['state']->value,
                'at' => $override['at']->format(\DateTimeInterface::ATOM),
            ], $report->overrides()),
            'history' => array_map(static fn(array $entry): array => [
                'state' => $entry['state']->value,
                'at' => $entry['at']->format(\DateTimeInterface::ATOM),
            ], $report->history()),
            'next_commands' => array_map(static fn(RunCommand $command): string => $command->value, $report->nextCommands()),
        ], JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR), OutputInterface::OUTPUT_RAW);
    }

    /**
     * The lines a writing command prints about the run before it asks for confirmation.
     *
     * @param string $action what the command is about to do to the run
     */
    public function plan(StatusReport $report, OutputInterface $output, string $action): void
    {
        $output->writeln(sprintf(
            '<info>Plan:</info> %s run %s, which stands at %s (key indices %s, new index %s).',
            $action,
            (string) $report->runId(),
            $report->state()->value ?? 'an unknown state',
            implode(', ', $report->sourceIndices()),
            $report->newIndex() === null ? '?' : (string) $report->newIndex(),
        ));
    }

    private function next(StatusReport $report, OutputInterface $output, string $storeOptions): void
    {
        $this->sections->nextCommands($output, array_map(
            static fn(RunCommand $command): string => sprintf(
                'key-rotator %s %s%s',
                $command->value,
                $storeOptions,
                in_array($command, [RunCommand::Rotate, RunCommand::Retire, RunCommand::Rollback], true)
                    ? ' (--probe-fcgi=… | --probe-url=… | --skip-web-probe)'
                    : '',
            ),
            $report->nextCommands(),
        ));
    }

    /**
     * Whether the key ring may hold the run's new key, so values may already sit under it.
     */
    private function holdsNewKey(RunState $state): bool
    {
        return !in_array($state, [RunState::Started, RunState::RolledBack, RunState::Purged], true);
    }
}
