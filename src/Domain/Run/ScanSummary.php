<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * What a scan left behind, in the terms a run decides on: how many values decrypt under each key index,
 * how many cannot be decrypted at all, how many are embedded inside larger values (counted, never
 * rewritten), how many columns the database stopped scanning before the end, and how many whole
 * ciphertexts sit under each key index in columns whose table has no row key.
 *
 * A value in a column without a row key is a whole ciphertext the tool can neither verify nor rewrite,
 * since its row cannot be addressed; it is not an embedded value. On a key index a step makes
 * unreadable it counts like a value that still decrypts there: only moving it by other means, or an
 * explicit acceptance of the loss, lets the step go on.
 *
 * Created through {@see ScanSummaryFactory}.
 */
final class ScanSummary
{
    /**
     * @var array<int, int> key index => verified values, in index order, zero counts left out
     */
    private readonly array $verifiedPerIndex;

    /**
     * @var array<int, int> key index => whole ciphertexts in columns without a row key, in index order, zero counts left out
     */
    private readonly array $withoutRowKeyPerIndex;

    /**
     * @param array<int, int> $verifiedPerIndex      key index => values that decrypt under that slot
     * @param int             $undecryptable         values no key of the ring decrypts
     * @param int             $embedded              values holding a ciphertext inside a larger value
     * @param int             $incompleteColumns     columns whose scan the database cut short
     * @param array<int, int> $withoutRowKeyPerIndex key index => whole ciphertexts under it in columns whose table has no row key
     *
     * @throws InvalidScanSummary when a count is negative or a key index is out of range
     */
    public function __construct(
        array $verifiedPerIndex,
        private readonly int $undecryptable,
        private readonly int $embedded,
        private readonly int $incompleteColumns,
        array $withoutRowKeyPerIndex,
    ) {
        $this->requireCountsPerIndex($verifiedPerIndex);
        $this->requireCountsPerIndex($withoutRowKeyPerIndex);
        foreach (['undecryptable' => $undecryptable, 'embedded' => $embedded, 'incomplete columns' => $incompleteColumns] as $name => $count) {
            if ($count < 0) {
                throw new InvalidScanSummary(sprintf('The count of %s cannot be negative.', $name));
            }
        }

        $this->verifiedPerIndex = $this->positive($verifiedPerIndex);
        $this->withoutRowKeyPerIndex = $this->positive($withoutRowKeyPerIndex);
    }

    /**
     * @return array<int, int> key index => verified values, in index order; an index without values is absent
     */
    public function verifiedPerIndex(): array
    {
        return $this->verifiedPerIndex;
    }

    public function verifiedOn(int $index): int
    {
        return $this->verifiedPerIndex[$index] ?? 0;
    }

    /**
     * @param list<int> $indices
     *
     * @return int the verified values on any of those indices
     */
    public function verifiedOnAny(array $indices): int
    {
        $total = 0;
        foreach (array_unique($indices) as $index) {
            $total += $this->verifiedOn($index);
        }

        return $total;
    }

    /**
     * @return array<int, int> key index => whole ciphertexts under it in columns without a row key, in index order
     */
    public function withoutRowKeyPerIndex(): array
    {
        return $this->withoutRowKeyPerIndex;
    }

    /**
     * @param list<int> $indices
     *
     * @return int the whole ciphertexts on any of those indices in columns without a row key
     */
    public function withoutRowKeyOnAny(array $indices): int
    {
        $total = 0;
        foreach (array_unique($indices) as $index) {
            $total += $this->withoutRowKeyPerIndex[$index] ?? 0;
        }

        return $total;
    }

    public function undecryptable(): int
    {
        return $this->undecryptable;
    }

    public function embedded(): int
    {
        return $this->embedded;
    }

    public function incompleteColumns(): int
    {
        return $this->incompleteColumns;
    }

    /**
     * Whether something was found that the scan could not judge: an embedded value or a column whose scan
     * was cut short. Values in columns without a row key are not among them: they are whole ciphertexts,
     * counted per key index.
     */
    public function hasUnjudgedValues(): bool
    {
        return $this->embedded > 0 || $this->incompleteColumns > 0;
    }

    /**
     * @return array{verified: list<array{index: int, count: int}>, undecryptable: int, embedded: int, incomplete_columns: int, without_row_key: list<array{index: int, count: int}>}
     */
    public function snapshot(): array
    {
        return [
            'verified' => $this->listed($this->verifiedPerIndex),
            'undecryptable' => $this->undecryptable,
            'embedded' => $this->embedded,
            'incomplete_columns' => $this->incompleteColumns,
            'without_row_key' => $this->listed($this->withoutRowKeyPerIndex),
        ];
    }

    /**
     * @param array<int, int> $perIndex
     *
     * @throws InvalidScanSummary when a count is negative or a key index is out of range
     */
    private function requireCountsPerIndex(array $perIndex): void
    {
        foreach ($perIndex as $index => $count) {
            if ($index < 0 || $index > Ciphertext::MAX_KEY_INDEX) {
                throw new InvalidScanSummary(sprintf('A key index lies between 0 and %d; %d was given.', Ciphertext::MAX_KEY_INDEX, $index));
            }
            if ($count < 0) {
                throw new InvalidScanSummary(sprintf('The count of key index %d cannot be negative.', $index));
            }
        }
    }

    /**
     * @param array<int, int> $perIndex
     *
     * @return array<int, int> the positive counts, in index order
     */
    private function positive(array $perIndex): array
    {
        $counts = array_filter($perIndex, static fn(int $count): bool => $count > 0);
        ksort($counts);

        return $counts;
    }

    /**
     * @param array<int, int> $perIndex
     *
     * @return list<array{index: int, count: int}>
     */
    private function listed(array $perIndex): array
    {
        $listed = [];
        foreach ($perIndex as $index => $count) {
            $listed[] = ['index' => $index, 'count' => $count];
        }

        return $listed;
    }
}
