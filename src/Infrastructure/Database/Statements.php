<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Runs statements on the store's database, prepared on the server once per text and reused.
 *
 * Positional parameters are bound with the type each value has, so an integer reaches the server as an
 * integer (a `LIMIT` needs one) and a string as its exact bytes.
 */
final class Statements
{
    /**
     * @var array<string, \PDOStatement>
     */
    private array $prepared = [];

    public function __construct(
        private readonly PdoConnectionProvider $database,
    ) {}

    /**
     * Prepares the statement (or reuses it) and runs it with the values bound to its `?` placeholders,
     * in order.
     *
     * @param list<int|float|string|bool|null> $values
     *
     * @throws \PDOException when the statement fails
     */
    public function run(string $sql, array $values = []): \PDOStatement
    {
        $statement = $this->prepared[$sql] ??= $this->database->connection()->prepare($sql);
        foreach ($values as $position => $value) {
            // A float travels as its shortest exact decimal form, so a key read back compares equal.
            $statement->bindValue($position + 1, is_float($value) ? var_export($value, true) : $value, match (true) {
                is_int($value) => \PDO::PARAM_INT,
                is_bool($value) => \PDO::PARAM_BOOL,
                $value === null => \PDO::PARAM_NULL,
                default => \PDO::PARAM_STR,
            });
        }
        $statement->execute();

        return $statement;
    }

    /**
     * Runs a statement that changes the schema; such statements are not kept prepared.
     *
     * @throws \PDOException when the statement fails
     */
    public function define(string $sql): void
    {
        $this->database->connection()->exec($sql);
    }
}
