<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;

/**
 * What a scan of the store's encrypted values found, read-only and free of secrets: it holds counts,
 * column names, configuration paths and ciphertexts as stored, never a key or a plaintext.
 *
 * - Columns whose rows can be identified, each with its counts per key index and verdict.
 * - Columns without a row key: their shape counts as discovery reported them; their values can be
 *   neither verified nor rewritten.
 * - Embedded candidates (a ciphertext inside a larger value: counted, never rewritten) and columns whose
 *   scan the database cut short, both taken from every candidate column.
 * - The encrypted `system` values of the deployment and the committed configuration, each with its
 *   verdict and its file.
 *
 * {@see summary()} turns the findings into what a run decides on: verified values per key index from the
 * database and both files, every value that does not decrypt or does not parse, the embedded values,
 * the columns whose scan was cut short, and, per key index, the whole ciphertexts in columns without a
 * row key. Those are not embedded values: they are values the tool can neither verify nor move, so on
 * an index a step makes unreadable they stand in the way like values that still decrypt there.
 *
 * Created through {@see ScanReportFactory}.
 *
 * @phpstan-type IndexTotals array{verified: int, retired_key: int, unknown_key: int, unsupported_cipher: int, authentication_failed: int, unparsable: int}
 */
final class ScanReport
{
    private readonly ScanSummary $summary;

    /**
     * @param list<ColumnFindings>     $columns        the columns whose values were verified
     * @param list<ColumnCandidate>    $withoutRowKey  the columns whose rows cannot be identified
     * @param list<SystemValueFinding> $systemValues   the encrypted values of both configuration files
     * @param float                    $elapsedSeconds how long the scan took
     * @param ScanSummaryFactory       $summaries      creates the summary
     *
     * @throws InvalidValue when the elapsed time is negative
     */
    public function __construct(
        private readonly array $columns,
        private readonly array $withoutRowKey,
        private readonly array $systemValues,
        private readonly float $elapsedSeconds,
        ScanSummaryFactory $summaries,
    ) {
        if ($elapsedSeconds < 0) {
            throw new InvalidValue('The time a scan took cannot be negative.');
        }
        $this->summary = $this->summarise($summaries);
    }

    /**
     * @return list<ColumnFindings>
     */
    public function columns(): array
    {
        return $this->columns;
    }

    /**
     * @return list<ColumnCandidate> the columns whose rows cannot be identified, with their shape counts
     */
    public function columnsWithoutRowKey(): array
    {
        return $this->withoutRowKey;
    }

    /**
     * @return list<ColumnCandidate> every candidate column holding values with a ciphertext embedded inside
     */
    public function embeddedCandidates(): array
    {
        return array_values(array_filter(
            $this->candidates(),
            static fn(ColumnCandidate $candidate): bool => $candidate->embeddedCount() > 0,
        ));
    }

    /**
     * @return list<ColumnCandidate> every candidate column whose scan the database cut short
     */
    public function incompleteColumns(): array
    {
        return array_values(array_filter(
            $this->candidates(),
            static fn(ColumnCandidate $candidate): bool => $candidate->scanIncomplete(),
        ));
    }

    /**
     * @param SystemValueSource|null $source only the values of that file, or of both when null
     *
     * @return list<SystemValueFinding>
     */
    public function systemValues(?SystemValueSource $source = null): array
    {
        if ($source === null) {
            return $this->systemValues;
        }

        return array_values(array_filter(
            $this->systemValues,
            static fn(SystemValueFinding $finding): bool => $finding->source() === $source,
        ));
    }

    /**
     * The counts per key index over the verified columns and both configuration files.
     *
     * @return array<int, IndexTotals> key index => counts, in index order
     */
    public function totalsPerIndex(): array
    {
        $totals = [];
        foreach ($this->columns as $findings) {
            foreach ($findings->perIndex() as $index => $counts) {
                foreach ($counts as $verdict => $count) {
                    $totals = $this->added($totals, $index, ValueVerdict::from($verdict), $count);
                }
            }
        }
        foreach ($this->systemValues as $finding) {
            $totals = $this->added($totals, $finding->keyIndex(), $finding->verdict(), 1);
        }
        ksort($totals);

        return $totals;
    }

    /**
     * How many values decrypt under any of those key indices, in the database and both files.
     *
     * @param list<int> $indices
     */
    public function verifiedOnAny(array $indices): int
    {
        return $this->summary->verifiedOnAny($indices);
    }

    public function summary(): ScanSummary
    {
        return $this->summary;
    }

    public function elapsedSeconds(): float
    {
        return $this->elapsedSeconds;
    }

    /**
     * The report as plain data with stable keys, for machine-readable output. It holds counts, names and
     * paths; never a key, a plaintext or a stored value.
     *
     * @return array{elapsed_seconds: float, summary: array{verified: list<array{index: int, count: int}>, undecryptable: int, embedded: int, incomplete_columns: int, without_row_key: list<array{index: int, count: int}>}, totals: list<array{index: int, verified: int, retired_key: int, unknown_key: int, unsupported_cipher: int, authentication_failed: int, unparsable: int}>, columns: list<array{column: string, row_key: list<string>, embedded: int, scan_incomplete: bool, indices: list<array{index: int, counts: array<string, int>}>}>, without_row_key: list<array{column: string, shape_counts: list<array{index: int, count: int}>, embedded: int, scan_incomplete: bool}>, system_values: list<array{source: string, path: string, key_index: int, verdict: string}>}
     */
    public function toArray(): array
    {
        $totals = [];
        foreach ($this->totalsPerIndex() as $index => $counts) {
            $totals[] = ['index' => $index] + $counts;
        }
        $columns = [];
        foreach ($this->columns as $findings) {
            $indices = [];
            foreach ($findings->perIndex() as $index => $counts) {
                $indices[] = ['index' => $index, 'counts' => $counts];
            }
            $columns[] = [
                'column' => $findings->column()->toString(),
                'row_key' => $findings->candidate()->rowKeyColumns(),
                'embedded' => $findings->candidate()->embeddedCount(),
                'scan_incomplete' => $findings->candidate()->scanIncomplete(),
                'indices' => $indices,
            ];
        }
        $withoutRowKey = [];
        foreach ($this->withoutRowKey as $candidate) {
            $shapeCounts = [];
            foreach ($candidate->shapeCounts() as $index => $count) {
                $shapeCounts[] = ['index' => $index, 'count' => $count];
            }
            $withoutRowKey[] = [
                'column' => $candidate->column()->toString(),
                'shape_counts' => $shapeCounts,
                'embedded' => $candidate->embeddedCount(),
                'scan_incomplete' => $candidate->scanIncomplete(),
            ];
        }
        $systemValues = [];
        foreach ($this->systemValues as $finding) {
            $systemValues[] = [
                'source' => $finding->source()->value,
                'path' => $finding->value()->pathString(),
                'key_index' => $finding->keyIndex(),
                'verdict' => $finding->verdict()->value,
            ];
        }

        return [
            'elapsed_seconds' => $this->elapsedSeconds,
            'summary' => $this->summary->snapshot(),
            'totals' => $totals,
            'columns' => $columns,
            'without_row_key' => $withoutRowKey,
            'system_values' => $systemValues,
        ];
    }

    /**
     * @return list<ColumnCandidate> every candidate column the scan saw
     */
    private function candidates(): array
    {
        return [
            ...array_map(static fn(ColumnFindings $findings): ColumnCandidate => $findings->candidate(), $this->columns),
            ...$this->withoutRowKey,
        ];
    }

    private function summarise(ScanSummaryFactory $summaries): ScanSummary
    {
        $verified = [];
        $undecryptable = 0;
        foreach ($this->totalsPerIndex() as $index => $counts) {
            $verified[$index] = $counts['verified'];
            $undecryptable += $counts['retired_key'] + $counts['unknown_key'] + $counts['unsupported_cipher']
                + $counts['authentication_failed'] + $counts['unparsable'];
        }
        $embedded = 0;
        foreach ($this->candidates() as $candidate) {
            $embedded += $candidate->embeddedCount();
        }
        $withoutRowKey = [];
        foreach ($this->withoutRowKey as $candidate) {
            foreach ($candidate->shapeCounts() as $index => $count) {
                $withoutRowKey[$index] = ($withoutRowKey[$index] ?? 0) + $count;
            }
        }

        return $summaries->create($verified, $undecryptable, $embedded, count($this->incompleteColumns()), $withoutRowKey);
    }

    /**
     * @param array<int, IndexTotals> $totals
     *
     * @return array<int, IndexTotals>
     */
    private function added(array $totals, int $index, ValueVerdict $verdict, int $count): array
    {
        $current = $totals[$index] ?? [
            'verified' => 0,
            'retired_key' => 0,
            'unknown_key' => 0,
            'unsupported_cipher' => 0,
            'authentication_failed' => 0,
            'unparsable' => 0,
        ];
        $current[$verdict->value] += $count;
        $totals[$index] = $current;

        return $totals;
    }
}
