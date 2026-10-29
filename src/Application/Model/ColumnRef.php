<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * A column of the store's database, named by its table without the table prefix, so the same reference
 * holds on every installation whatever prefix it uses.
 *
 * Created through {@see ColumnRefFactory}.
 */
final class ColumnRef
{
    private const MAX_IDENTIFIER_LENGTH = 64;

    /**
     * @param string $table  the table name without the prefix
     * @param string $column the column name
     *
     * @throws InvalidValue when a name is empty, longer than 64 characters, or holds a dot, a NUL byte or a backtick
     */
    public function __construct(
        private readonly string $table,
        private readonly string $column,
    ) {
        foreach (['table' => $table, 'column' => $column] as $what => $name) {
            if ($name === '' || strlen($name) > self::MAX_IDENTIFIER_LENGTH || strpbrk($name, ".\0`") !== false) {
                throw new InvalidValue(sprintf('A %s name is 1 to %d characters without a dot, a NUL byte or a backtick.', $what, self::MAX_IDENTIFIER_LENGTH));
            }
        }
    }

    public function table(): string
    {
        return $this->table;
    }

    public function column(): string
    {
        return $this->column;
    }

    /**
     * The column as the database names it on an installation with that table prefix:
     * `<prefix><table>.<column>`.
     */
    public function qualified(string $prefix): string
    {
        return $prefix . $this->table . '.' . $this->column;
    }

    /**
     * `<table>.<column>`, the table without its prefix.
     */
    public function toString(): string
    {
        return $this->qualified('');
    }

    public function equals(self $other): bool
    {
        return $this->table === $other->table && $this->column === $other->column;
    }
}
