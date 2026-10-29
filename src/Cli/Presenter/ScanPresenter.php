<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Cli\Presenter;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * Writes a scan report: as text for the operator, or as JSON for a script.
 *
 * The JSON is stable: an object with `format_version` (1), `elapsed_seconds`, `summary` (verified values
 * per index, undecryptable, embedded, incomplete columns), `totals` (per key index: verified, retired_key,
 * unknown_key, unsupported_cipher, authentication_failed, unparsable), `columns` (per `table.column`: its
 * row key, embedded values, whether the scan was cut short, and the counts per index by reason),
 * `without_row_key` (columns holding ciphertexts whose rows cannot be identified, with their counts per
 * index) and `system_values` (per configuration value: source `env` or `committed`, path, key index,
 * verdict). Counts only: no value, plaintext or ciphertext is ever written.
 */
final class ScanPresenter
{
    public const FORMAT_VERSION = 1;

    public function __construct(
        private readonly ReportSections $sections,
    ) {}

    public function json(ScanReport $report, OutputInterface $output): void
    {
        $output->writeln(
            json_encode(['format_version' => self::FORMAT_VERSION] + $report->toArray(), JSON_PRETTY_PRINT | JSON_UNESCAPED_SLASHES | JSON_THROW_ON_ERROR),
            OutputInterface::OUTPUT_RAW,
        );
    }

    public function text(ScanReport $report, OutputInterface $output): void
    {
        $output->writeln('<info>Encrypted values per key index</info>');
        $this->sections->scan($output, $report);

        foreach ($report->columns() as $findings) {
            $output->writeln(sprintf('  %s', $this->sections->escape($findings->column()->toString())), OutputInterface::VERBOSITY_VERBOSE);
            foreach ($findings->perIndex() as $index => $counts) {
                $output->writeln(sprintf('    key index %d: %s', $index, $this->counts($counts)), OutputInterface::VERBOSITY_VERBOSE);
            }
        }

        $output->writeln(sprintf('Scanned %d column(s) in %.1f s.', count($report->columns()), $report->elapsedSeconds()));
    }

    /**
     * @param array<string, int> $counts
     */
    private function counts(array $counts): string
    {
        $parts = [];
        foreach ($counts as $verdict => $count) {
            $parts[] = sprintf('%d %s', $count, str_replace('_', ' ', $verdict));
        }

        return implode(', ', $parts);
    }
}
