<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;

/**
 * A database of its own for one test, on the server the integration environment names (`DB_SERVICE`,
 * `DB_USER`, `DB_PASSWORD`): created empty, reached through connections of the test's own, and dropped
 * afterwards.
 */
final class TestDatabase
{
    private ?\PDO $connection = null;

    private function __construct(
        private readonly \PDO $server,
        private readonly string $name,
        private readonly string $prefix,
    ) {}

    /**
     * Creates an empty database.
     *
     * @param string $prefix the table prefix the store's configuration names
     */
    public static function create(string $prefix = ''): self
    {
        $server = new \PDO(sprintf('mysql:host=%s;charset=utf8mb4', self::environment('DB_SERVICE')), self::environment('DB_USER'), self::environment('DB_PASSWORD'), [
            \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
        ]);
        $name = 'kr_' . bin2hex(random_bytes(6));
        $server->exec(sprintf('CREATE DATABASE `%s` CHARACTER SET utf8mb4 COLLATE utf8mb4_general_ci', $name));

        return new self($server, $name, $prefix);
    }

    public function drop(): void
    {
        $this->connection = null;
        $this->server->exec(sprintf('DROP DATABASE IF EXISTS `%s`', $this->name));
    }

    /**
     * The connection settings the store's configuration would hold for this database.
     */
    public function settings(string $initStatements = ''): DatabaseSettings
    {
        return new DatabaseSettings(
            self::environment('DB_SERVICE'),
            3306,
            null,
            $this->name,
            self::environment('DB_USER'),
            self::environment('DB_PASSWORD'),
            $this->prefix,
            $initStatements,
        );
    }

    /**
     * A deployment configuration naming this database, with a fresh key ring.
     */
    public function deploymentConfig(string $initStatements = ''): InMemoryDeploymentConfig
    {
        $ring = CryptoServices::shared()->ringParser()->parse(KeyMaterial::base64Key());

        return new InMemoryDeploymentConfig($ring, databaseSettings: $this->settings($initStatements));
    }

    /**
     * The test's own connection to the database, apart from any connection an adapter opens: it plays
     * the store's application.
     */
    public function connection(): \PDO
    {
        return $this->connection ??= $this->connect();
    }

    /**
     * Another connection of its own, for a second client acting at the same time.
     */
    public function connect(): \PDO
    {
        return new \PDO(
            sprintf('mysql:host=%s;dbname=%s;charset=utf8mb4', self::environment('DB_SERVICE'), $this->name),
            self::environment('DB_USER'),
            self::environment('DB_PASSWORD'),
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION, \PDO::ATTR_EMULATE_PREPARES => false, \PDO::ATTR_STRINGIFY_FETCHES => false],
        );
    }

    /**
     * The table's name in the database: the prefix and the name.
     */
    public function table(string $name): string
    {
        return $this->prefix . $name;
    }

    public function name(): string
    {
        return $this->name;
    }

    /**
     * Whether the server is MySQL rather than MariaDB.
     */
    public function isMysql(): bool
    {
        $statement = $this->server->query('SELECT VERSION()');
        $version = $statement === false ? null : $statement->fetchColumn();

        return is_string($version) && !str_contains(strtolower($version), 'mariadb');
    }

    /**
     * The server, outside any database: for settings that apply to the whole server.
     */
    public function server(): \PDO
    {
        return $this->server;
    }

    /**
     * Runs statements on the test's own connection.
     */
    public function exec(string ...$statements): void
    {
        foreach ($statements as $statement) {
            $this->connection()->exec($statement);
        }
    }

    /**
     * @param list<int|string|null> $parameters
     *
     * @return list<array<string, mixed>>
     */
    public function select(string $sql, array $parameters = []): array
    {
        $statement = $this->connection()->prepare($sql);
        $statement->execute($parameters);
        $rows = [];
        while (($row = $statement->fetch(\PDO::FETCH_ASSOC)) !== false) {
            $named = [];
            foreach ($row as $column => $value) {
                $named[(string) $column] = $value;
            }
            $rows[] = $named;
        }

        return $rows;
    }

    /**
     * @param list<int|string|null> $parameters
     */
    public function value(string $sql, array $parameters = []): mixed
    {
        $statement = $this->connection()->prepare($sql);
        $statement->execute($parameters);

        return $statement->fetchColumn();
    }

    private static function environment(string $name): string
    {
        $value = getenv($name);
        if (!is_string($value) || $value === '') {
            throw new \RuntimeException(sprintf('The integration tests need the environment variable %s; run them through compose.yaml.', $name));
        }

        return $value;
    }
}
