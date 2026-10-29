<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * What a scan found in one column whose rows can be identified: per key index, how many of its values
 * got each {@see ValueVerdict}, next to what discovery reported about the column.
 *
 * Created through {@see ColumnFindingsFactory}.
 */
final class ColumnFindings
{
    /**
     * @var array<int, array<string, int>>
     */
    private readonly array $perIndex;

    /**
     * @param ColumnCandidate                $candidate the column as discovery reported it
     * @param array<int, array<string, int>> $perIndex  key index => verdict value => values with that verdict
     *
     * @throws InvalidValue when a key index, a verdict or a count is out of range
     */
    public function __construct(
        private readonly ColumnCandidate $candidate,
        array $perIndex,
    ) {
        $normalised = [];
        foreach ($perIndex as $index => $counts) {
            if ($index < 0) {
                throw new InvalidValue(sprintf('The findings of %s hold a negative key index.', $candidate->column()->toString()));
            }
            $normalised[$index] = [];
            foreach ($counts as $verdict => $count) {
                if (ValueVerdict::tryFrom($verdict) === null || $count < 0) {
                    throw new InvalidValue(sprintf('The findings of %s hold an unknown verdict or a negative count.', $candidate->column()->toString()));
                }
                if ($count > 0) {
                    $normalised[$index][$verdict] = $count;
                }
            }
        }
        ksort($normalised);
        $this->perIndex = $normalised;
    }

    public function column(): ColumnRef
    {
        return $this->candidate->column();
    }

    public function candidate(): ColumnCandidate
    {
        return $this->candidate;
    }

    /**
     * @return list<int> the key indices values were read under, in index order
     */
    public function indices(): array
    {
        return array_keys($this->perIndex);
    }

    /**
     * How many values under that key index got that verdict.
     */
    public function count(int $index, ValueVerdict $verdict): int
    {
        return $this->perIndex[$index][$verdict->value] ?? 0;
    }

    public function verifiedOn(int $index): int
    {
        return $this->count($index, ValueVerdict::Verified);
    }

    /**
     * @return array<int, array<string, int>> key index => verdict value => count; zero counts left out
     */
    public function perIndex(): array
    {
        return $this->perIndex;
    }
}
