<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Turns the names the tool uses (tables without the store's table prefix) into the names the database
 * knows, quoted for a statement.
 *
 * Only names made of letters, digits, `_` and `$`, at most 64 characters, are quoted, with backticks;
 * any other name is refused, never escaped, so no name read from the schema can change a statement.
 */
final class TableNames
{
    public const JOURNAL = 'encryption_key_rotation_journal';
    public const RUN_REGISTRY = 'encryption_key_rotation_run';

    private const IDENTIFIER = '/^[A-Za-z0-9_$]{1,64}$/D';

    public function __construct(
        private readonly PdoConnectionProvider $database,
    ) {}

    /**
     * Whether a name can be quoted.
     */
    public function isSupported(string $identifier): bool
    {
        return preg_match(self::IDENTIFIER, $identifier) === 1;
    }

    /**
     * Whether the table's name in the database, the prefix included, can be quoted.
     */
    public function isSupportedTable(string $table): bool
    {
        return $this->isSupported($this->database->tablePrefix() . $table);
    }

    /**
     * The table's name in the database: the prefix and the name, unquoted.
     *
     * @throws UnsupportedIdentifier when the prefixed name cannot be quoted
     */
    public function physical(string $table): string
    {
        $name = $this->database->tablePrefix() . $table;
        $this->assertSupported($name);

        return $name;
    }

    /**
     * The table's name in the database, quoted for a statement.
     *
     * @throws UnsupportedIdentifier when the prefixed name cannot be quoted
     */
    public function table(string $table): string
    {
        return '`' . $this->physical($table) . '`';
    }

    /**
     * A column name, quoted for a statement.
     *
     * @throws UnsupportedIdentifier when the name cannot be quoted
     */
    public function column(string $column): string
    {
        $this->assertSupported($column);

        return '`' . $column . '`';
    }

    /**
     * The name the tool uses for a table of the database: without the prefix, or null when the table
     * does not carry the store's prefix and so is not one of the store's tables.
     */
    public function logical(string $physical): ?string
    {
        $prefix = $this->database->tablePrefix();
        if ($physical === $prefix || !str_starts_with($physical, $prefix)) {
            return null;
        }

        return substr($physical, strlen($prefix));
    }

    /**
     * The tool's journal, quoted for a statement.
     */
    public function journal(): string
    {
        return $this->table(self::JOURNAL);
    }

    /**
     * The tool's record of the run that holds the store, quoted for a statement.
     */
    public function runRegistry(): string
    {
        return $this->table(self::RUN_REGISTRY);
    }

    private function assertSupported(string $identifier): void
    {
        if (!$this->isSupported($identifier)) {
            throw new UnsupportedIdentifier(sprintf(
                'The name "%s" is not 1 to 64 letters, digits, "_" or "$"; the tool does not put it into a statement.',
                $identifier,
            ));
        }
    }
}
