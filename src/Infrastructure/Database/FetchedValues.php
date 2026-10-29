<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Reads fetched rows as the types the statement selected, and fails loudly on anything else: a value of
 * another type means the statement and the schema disagree, never a value to guess at.
 */
final class FetchedValues
{
    /**
     * Every remaining row of the statement, each keyed by column label.
     *
     * @return list<array<string, mixed>>
     */
    public function all(\PDOStatement $statement): array
    {
        $rows = [];
        while (($row = $statement->fetch(\PDO::FETCH_ASSOC)) !== false) {
            $named = [];
            foreach ($row as $label => $value) {
                $named[(string) $label] = $value;
            }
            $rows[] = $named;
        }

        return $rows;
    }

    /**
     * Every remaining row of the statement, each as its values in select order.
     *
     * @return list<list<mixed>>
     */
    public function positional(\PDOStatement $statement): array
    {
        $rows = [];
        while (($row = $statement->fetch(\PDO::FETCH_NUM)) !== false) {
            $rows[] = $row;
        }

        return $rows;
    }

    /**
     * @param array<string, mixed> $row
     */
    public function string(array $row, string $label): string
    {
        $value = $row[$label] ?? null;
        if (!is_string($value)) {
            throw new \UnexpectedValueException(sprintf('The fetched column "%s" is not a string.', $label));
        }

        return $value;
    }

    /**
     * @param array<string, mixed> $row
     */
    public function nullableString(array $row, string $label): ?string
    {
        $value = $row[$label] ?? null;

        return $value === null ? null : $this->string($row, $label);
    }

    /**
     * An integer column; a server that hands integers over as decimal text is read the same.
     *
     * @param array<string, mixed> $row
     */
    public function int(array $row, string $label): int
    {
        $value = $row[$label] ?? null;
        if (is_int($value)) {
            return $value;
        }
        if (is_string($value) && preg_match('/^-?[0-9]+$/D', $value) === 1) {
            return (int) $value;
        }

        throw new \UnexpectedValueException(sprintf('The fetched column "%s" is not an integer.', $label));
    }

    /**
     * A row key value as the database returned it.
     *
     * @return int|float|string
     */
    public function keyValue(mixed $value, string $column): int|float|string
    {
        if (is_int($value) || is_float($value) || is_string($value)) {
            return $value;
        }

        throw new \UnexpectedValueException(sprintf('The key column "%s" holds a value that cannot identify a row.', $column));
    }
}
