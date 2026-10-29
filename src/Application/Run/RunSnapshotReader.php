<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidRunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;

/**
 * Reads a saved run back from the data {@see RotationRun::snapshot()} wrote, as a run store decoded it.
 *
 * Every field is checked for presence and type before the run is restored, and the run's own rules
 * check the rest; whatever does not hold makes the whole snapshot corrupt, naming the run and the field.
 * A moment must be written exactly as the snapshot writes it, so a restored run snapshots back to the
 * same data.
 */
final class RunSnapshotReader
{
    private const TIMESTAMP_SHAPE = '/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}\.[0-9]{6}[+-][0-9]{2}:[0-9]{2}$/D';

    public function __construct(
        private readonly RotationRunFactory $runs,
        private readonly RunIdFactory $ids,
        private readonly ScanSummaryFactory $summaries,
        private readonly DateTimeFactory $moments,
    ) {}

    /**
     * @param string $runId    the id the store holds the snapshot under
     * @param mixed  $snapshot the decoded snapshot
     *
     * @throws CorruptRunFile when the snapshot does not describe that run
     */
    public function read(string $runId, mixed $snapshot): RotationRun
    {
        if (!is_array($snapshot)) {
            throw $this->corrupt($runId, 'the run record is not an object');
        }
        $format = $this->int($runId, $snapshot, 'format');
        if ($format !== RotationRun::SNAPSHOT_FORMAT) {
            throw $this->corrupt($runId, sprintf('the record format %d is not the supported format %d', $format, RotationRun::SNAPSHOT_FORMAT));
        }
        $id = $this->string($runId, $snapshot, 'id');
        if ($id !== $runId) {
            throw $this->corrupt($runId, 'the record names another run');
        }

        try {
            return $this->runs->restore(
                id: $this->ids->create($id),
                ringFingerprintBefore: $this->string($runId, $snapshot, 'ring_fingerprint_before'),
                oldUsableIndices: $this->intList($runId, $snapshot, 'old_usable_indices'),
                activeIndexBefore: $this->int($runId, $snapshot, 'active_index_before'),
                startedAt: $this->moment($runId, $this->string($runId, $snapshot, 'started_at'), 'started_at'),
                state: $this->state($runId, $this->string($runId, $snapshot, 'state'), 'state'),
                newIndex: $this->nullableInt($runId, $snapshot, 'new_index'),
                ringFingerprint: $this->string($runId, $snapshot, 'ring_fingerprint'),
                intendedRingFingerprint: $this->nullableString($runId, $snapshot, 'intended_ring_fingerprint'),
                lastRingWriteAt: $this->nullableMoment($runId, $snapshot, 'last_ring_write_at'),
                probeSkipped: $this->bool($runId, $snapshot, 'probe_skipped'),
                lastSummary: $this->summary($runId, $snapshot),
                configCacheCleaned: $this->bool($runId, $snapshot, 'config_cache_cleaned'),
                rolledBackFrom: $this->nullableState($runId, $snapshot, 'rolled_back_from'),
                overrides: $this->overrides($runId, $snapshot),
                history: $this->history($runId, $snapshot),
            );
        } catch (InvalidRun|InvalidRunId|InvalidScanSummary $invalid) {
            throw $this->corrupt($runId, $invalid->getMessage(), $invalid);
        }
    }

    /**
     * @param array<mixed> $snapshot
     */
    private function summary(string $runId, array $snapshot): ?ScanSummary
    {
        $summary = $this->field($runId, $snapshot, 'last_summary');
        if ($summary === null) {
            return null;
        }
        if (!is_array($summary)) {
            throw $this->corrupt($runId, 'the field "last_summary" is not an object');
        }
        return $this->summaries->create(
            $this->countsPerIndex($runId, $summary, 'verified'),
            $this->int($runId, $summary, 'undecryptable', 'last_summary.undecryptable'),
            $this->int($runId, $summary, 'embedded', 'last_summary.embedded'),
            $this->int($runId, $summary, 'incomplete_columns', 'last_summary.incomplete_columns'),
            // A record written before values in columns without a row key were counted per key index has
            // no such list; it counted those columns among the incomplete ones instead.
            array_key_exists('without_row_key', $summary) ? $this->countsPerIndex($runId, $summary, 'without_row_key') : [],
        );
    }

    /**
     * @param array<mixed> $summary
     *
     * @return array<int, int> key index => count
     */
    private function countsPerIndex(string $runId, array $summary, string $key): array
    {
        $field = 'last_summary.' . $key;
        $counts = [];
        foreach ($this->list($runId, $summary, $key, $field) as $entry) {
            if (!is_array($entry)) {
                throw $this->corrupt($runId, sprintf('an entry of "%s" is not an object', $field));
            }
            $index = $this->int($runId, $entry, 'index', $field . '.index');
            if (array_key_exists($index, $counts)) {
                throw $this->corrupt($runId, sprintf('"%s" lists the key index %d twice', $field, $index));
            }
            $counts[$index] = $this->int($runId, $entry, 'count', $field . '.count');
        }

        return $counts;
    }

    /**
     * @param array<mixed> $snapshot
     *
     * @return list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}>
     */
    private function overrides(string $runId, array $snapshot): array
    {
        $overrides = [];
        foreach ($this->list($runId, $snapshot, 'overrides') as $entry) {
            if (!is_array($entry)) {
                throw $this->corrupt($runId, 'an entry of "overrides" is not an object');
            }
            $name = $this->string($runId, $entry, 'override', 'overrides.override');
            $override = RunOverride::tryFrom($name)
                ?? throw $this->corrupt($runId, sprintf('"overrides" names the unknown override "%s"', $name));
            $overrides[] = [
                'override' => $override,
                'state' => $this->state($runId, $this->string($runId, $entry, 'state', 'overrides.state'), 'overrides.state'),
                'at' => $this->moment($runId, $this->string($runId, $entry, 'at', 'overrides.at'), 'overrides.at'),
            ];
        }

        return $overrides;
    }

    /**
     * @param array<mixed> $snapshot
     *
     * @return list<array{state: RunState, at: \DateTimeImmutable}>
     */
    private function history(string $runId, array $snapshot): array
    {
        $history = [];
        foreach ($this->list($runId, $snapshot, 'history') as $entry) {
            if (!is_array($entry)) {
                throw $this->corrupt($runId, 'an entry of "history" is not an object');
            }
            $history[] = [
                'state' => $this->state($runId, $this->string($runId, $entry, 'state', 'history.state'), 'history.state'),
                'at' => $this->moment($runId, $this->string($runId, $entry, 'at', 'history.at'), 'history.at'),
            ];
        }
        if ($history === []) {
            throw $this->corrupt($runId, 'the field "history" is empty');
        }

        return $history;
    }

    private function state(string $runId, string $value, string $field): RunState
    {
        return RunState::tryFrom($value)
            ?? throw $this->corrupt($runId, sprintf('the field "%s" names the unknown state "%s"', $field, $value));
    }

    /**
     * @param array<mixed> $data
     */
    private function nullableState(string $runId, array $data, string $key): ?RunState
    {
        $value = $this->nullableString($runId, $data, $key);

        return $value === null ? null : $this->state($runId, $value, $key);
    }

    private function moment(string $runId, string $value, string $field): \DateTimeImmutable
    {
        if (preg_match(self::TIMESTAMP_SHAPE, $value) !== 1) {
            throw $this->corrupt($runId, sprintf('the field "%s" is not a moment written as %s', $field, RotationRun::TIMESTAMP_FORMAT));
        }
        try {
            $moment = $this->moments->create($value);
        } catch (\Exception $invalid) {
            throw $this->corrupt($runId, sprintf('the field "%s" is not a valid moment', $field), $invalid);
        }
        if ($moment->format(RotationRun::TIMESTAMP_FORMAT) !== $value) {
            throw $this->corrupt($runId, sprintf('the field "%s" is not a valid moment', $field));
        }

        return $moment;
    }

    /**
     * @param array<mixed> $data
     */
    private function nullableMoment(string $runId, array $data, string $key): ?\DateTimeImmutable
    {
        $value = $this->nullableString($runId, $data, $key);

        return $value === null ? null : $this->moment($runId, $value, $key);
    }

    /**
     * @param array<mixed> $data
     */
    private function string(string $runId, array $data, string $key, ?string $field = null): string
    {
        $value = $this->field($runId, $data, $key, $field);

        return is_string($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is not a string', $field ?? $key));
    }

    /**
     * @param array<mixed> $data
     */
    private function nullableString(string $runId, array $data, string $key): ?string
    {
        $value = $this->field($runId, $data, $key);

        return $value === null || is_string($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is neither a string nor null', $key));
    }

    /**
     * @param array<mixed> $data
     */
    private function int(string $runId, array $data, string $key, ?string $field = null): int
    {
        $value = $this->field($runId, $data, $key, $field);

        return is_int($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is not an integer', $field ?? $key));
    }

    /**
     * @param array<mixed> $data
     */
    private function nullableInt(string $runId, array $data, string $key): ?int
    {
        $value = $this->field($runId, $data, $key);

        return $value === null || is_int($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is neither an integer nor null', $key));
    }

    /**
     * @param array<mixed> $data
     */
    private function bool(string $runId, array $data, string $key): bool
    {
        $value = $this->field($runId, $data, $key);

        return is_bool($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is not a boolean', $key));
    }

    /**
     * @param array<mixed> $data
     *
     * @return list<int>
     */
    private function intList(string $runId, array $data, string $key): array
    {
        $values = [];
        foreach ($this->list($runId, $data, $key) as $value) {
            $values[] = is_int($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" holds a value that is not an integer', $key));
        }

        return $values;
    }

    /**
     * @param array<mixed> $data
     *
     * @return list<mixed>
     */
    private function list(string $runId, array $data, string $key, ?string $field = null): array
    {
        $value = $this->field($runId, $data, $key, $field);

        return is_array($value) && array_is_list($value) ? $value : throw $this->corrupt($runId, sprintf('the field "%s" is not a list', $field ?? $key));
    }

    /**
     * @param array<mixed> $data
     */
    private function field(string $runId, array $data, string $key, ?string $field = null): mixed
    {
        return array_key_exists($key, $data) ? $data[$key] : throw $this->corrupt($runId, sprintf('the field "%s" is missing', $field ?? $key));
    }

    private function corrupt(string $runId, string $reason, ?\Throwable $previous = null): CorruptRunFile
    {
        return new CorruptRunFile(sprintf('The record of run %s is corrupt: %s.', $runId, $reason), 0, $previous);
    }
}
