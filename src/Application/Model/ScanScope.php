<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Which columns a scan leaves out. A pattern is `table` (every column of matching tables) or
 * `table.column`; `*` stands for any run of characters, possibly empty. Tables are named without the
 * table prefix, and names compare case-sensitively, as the database compares them on Linux.
 *
 * Created through {@see ScanScopeFactory}.
 */
final class ScanScope
{
    private const PATTERN_SHAPE = '/^[A-Za-z0-9_$*]+(\.[A-Za-z0-9_$*]+)?$/D';

    /**
     * @var list<array{table: string, column: string|null}> compiled patterns
     */
    private readonly array $compiled;

    /**
     * @param list<string> $exclusions `table` or `table.column` patterns, `*` as the wildcard
     *
     * @throws InvalidValue when a pattern is empty or holds characters a table or column name cannot
     */
    public function __construct(
        private readonly array $exclusions,
    ) {
        $compiled = [];
        foreach ($exclusions as $pattern) {
            if (preg_match(self::PATTERN_SHAPE, $pattern) !== 1) {
                throw new InvalidValue(sprintf(
                    'An exclusion is "table" or "table.column" made of letters, digits, "_", "$" and "*"; "%s" is not.',
                    $pattern,
                ));
            }
            $parts = explode('.', $pattern, 2);
            $compiled[] = [
                'table' => $this->regex($parts[0]),
                'column' => isset($parts[1]) ? $this->regex($parts[1]) : null,
            ];
        }
        $this->compiled = $compiled;
    }

    /**
     * @return list<string> the exclusion patterns, as given
     */
    public function exclusions(): array
    {
        return $this->exclusions;
    }

    /**
     * Whether a pattern leaves that column out of the scan.
     */
    public function excludes(ColumnRef $column): bool
    {
        foreach ($this->compiled as $pattern) {
            if (preg_match($pattern['table'], $column->table()) !== 1) {
                continue;
            }
            if ($pattern['column'] === null || preg_match($pattern['column'], $column->column()) === 1) {
                return true;
            }
        }

        return false;
    }

    private function regex(string $glob): string
    {
        return '/^' . str_replace('\*', '.*', preg_quote($glob, '/')) . '$/D';
    }
}
