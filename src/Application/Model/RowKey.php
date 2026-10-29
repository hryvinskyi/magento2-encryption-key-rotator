<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Identifies one row of a table: its key columns, in key order, each with its value.
 *
 * The order is part of the key: {@see toJson()} writes the columns in that order, so the same row always
 * yields the same JSON and the journal can store and compare it as text. Values are integers, floats,
 * booleans or UTF-8 strings, the values JSON carries exactly.
 *
 * Created through {@see RowKeyFactory}.
 */
final class RowKey
{
    /**
     * @var array<string, int|float|string|bool>
     */
    private readonly array $values;

    /**
     * @param array<array-key, int|float|string|bool> $values key column => value, in key order
     *
     * @throws InvalidValue when no column is given, a column name is empty, or a string value is not UTF-8
     */
    public function __construct(array $values)
    {
        if ($values === []) {
            throw new InvalidValue('A row key has at least one column.');
        }
        $normalised = [];
        foreach ($values as $column => $value) {
            $name = (string) $column;
            if ($name === '') {
                throw new InvalidValue('A row key column has a name.');
            }
            if (is_string($value) && preg_match('//u', $value) !== 1) {
                throw new InvalidValue(sprintf('The row key column "%s" holds bytes that are not UTF-8; such a row cannot be journaled.', $name));
            }
            $normalised[$name] = $value;
        }
        $this->values = $normalised;
    }

    /**
     * @return array<string, int|float|string|bool> key column => value, in key order
     */
    public function values(): array
    {
        return $this->values;
    }

    /**
     * @return list<string> the key columns, in key order
     */
    public function columns(): array
    {
        return array_map(strval(...), array_keys($this->values));
    }

    /**
     * The key as a JSON object, its columns in key order: the same row always gives the same text.
     */
    public function toJson(): string
    {
        return json_encode(
            $this->values,
            JSON_THROW_ON_ERROR | JSON_FORCE_OBJECT | JSON_UNESCAPED_SLASHES | JSON_UNESCAPED_UNICODE | JSON_PRESERVE_ZERO_FRACTION,
        );
    }

    /**
     * Two keys are equal when they name the same columns, in the same order, with the same values.
     */
    public function equals(self $other): bool
    {
        return $this->toJson() === $other->toJson();
    }
}
