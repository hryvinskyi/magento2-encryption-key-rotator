<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;

/**
 * What moving a column's values between keys did, and what it left where it was:
 * - the values rewritten, per column;
 * - the rows a compare-and-swap still missed in the last pass (their value changed again in between);
 * - the values left alone because they do not decrypt under the source key, per column and verdict.
 *
 * Values that remain are a result for the operator, not a failure: a later pass or the next scan picks
 * them up.
 *
 * Created through {@see ReencryptionOutcomeFactory}.
 */
final class ReencryptionOutcome
{
    /**
     * @param array<string, int>                $applied   `table.column` => values rewritten
     * @param list<Conflict>                    $conflicts the rows the last pass could not write
     * @param array<string, array<string, int>> $skipped   `table.column` => verdict value => values left alone
     * @param int                               $passes    how many passes ran
     */
    public function __construct(
        private readonly array $applied,
        private readonly array $conflicts,
        private readonly array $skipped,
        private readonly int $passes,
    ) {}

    /**
     * @return array<string, int> `table.column` => values rewritten
     */
    public function applied(): array
    {
        return $this->applied;
    }

    public function appliedTo(ColumnRef $column): int
    {
        return $this->applied[$column->toString()] ?? 0;
    }

    public function appliedTotal(): int
    {
        return array_sum($this->applied);
    }

    /**
     * @return list<Conflict>
     */
    public function conflicts(): array
    {
        return $this->conflicts;
    }

    /**
     * @return array<string, array<string, int>> `table.column` => verdict value => values left alone
     */
    public function skipped(): array
    {
        return $this->skipped;
    }

    public function skippedIn(ColumnRef $column, ValueVerdict $verdict): int
    {
        return $this->skipped[$column->toString()][$verdict->value] ?? 0;
    }

    public function skippedTotal(): int
    {
        $total = 0;
        foreach ($this->skipped as $counts) {
            $total += array_sum($counts);
        }

        return $total;
    }

    /**
     * Values still under a source key: missed by the last pass or not decryptable under it.
     */
    public function remainingTotal(): int
    {
        return count($this->conflicts) + $this->skippedTotal();
    }

    public function passes(): int
    {
        return $this->passes;
    }
}
