<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DatabaseUnavailable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;

/**
 * The store's database as the deployment configuration names it: one connection per process, opened on
 * first use, and the table prefix.
 *
 * The connection reports errors as exceptions, prepares statements on the server and returns numbers
 * as numbers. It runs the configured init statements and leaves everything else, the SQL mode and the
 * transaction isolation level included, as the server sets them: a compare-and-swap on the exact old
 * bytes is correct under the default REPEATABLE READ, while READ COMMITTED would make every UPDATE fail
 * on a server that logs statements rather than rows.
 *
 * Nothing is read or opened before the first call: the store's root is only known once a command runs.
 */
final class PdoConnectionProvider
{
    private const CONNECT_TIMEOUT_SECONDS = 10;
    private const HOST_WITH_PORT = '/^(?<host>\[[^\]]+\]|[^:]+):(?<port>[0-9]{1,5})$/D';

    private ?\PDO $connection = null;

    private ?DatabaseSettings $settings = null;

    public function __construct(
        private readonly DeploymentConfigReader $deploymentConfig,
        private readonly PdoFactory $pdos,
    ) {}

    /**
     * The connection, opened on the first call.
     *
     * @throws DatabaseUnavailable when the server cannot be reached, refuses the login or the init statements
     */
    public function connection(): \PDO
    {
        if ($this->connection !== null) {
            return $this->connection;
        }
        $settings = $this->settings();
        try {
            $connection = $this->pdos->create($this->dsn($settings), $settings->user(), $settings->password(), [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_EMULATE_PREPARES => false,
                \PDO::ATTR_STRINGIFY_FETCHES => false,
                \PDO::ATTR_TIMEOUT => self::CONNECT_TIMEOUT_SECONDS,
            ]);
        } catch (\PDOException $exception) {
            // The driver's message and trace may carry the login; only the place and the code leave here.
            throw new DatabaseUnavailable(sprintf(
                'Cannot connect to the database "%s" on %s (error %s).',
                $settings->dbname(),
                $this->where($settings),
                $this->errorCode($exception),
            ));
        }
        $this->runInitStatements($connection, $settings);

        return $this->connection = $connection;
    }

    /**
     * The prefix every table name of the store carries, possibly empty.
     */
    public function tablePrefix(): string
    {
        return $this->settings()->tablePrefix();
    }

    private function settings(): DatabaseSettings
    {
        return $this->settings ??= $this->deploymentConfig->databaseSettings();
    }

    private function runInitStatements(\PDO $connection, DatabaseSettings $settings): void
    {
        if (trim($settings->initStatements()) === '') {
            return;
        }
        try {
            $connection->exec($settings->initStatements());
        } catch (\PDOException $exception) {
            throw new DatabaseUnavailable(sprintf(
                'The database "%s" on %s refused the configured init statements (error %s).',
                $settings->dbname(),
                $this->where($settings),
                $this->errorCode($exception),
            ));
        }
    }

    private function dsn(DatabaseSettings $settings): string
    {
        $socket = $settings->socket();
        if ($socket !== null && $socket !== '') {
            return sprintf('mysql:unix_socket=%s;dbname=%s;charset=utf8mb4', $socket, $settings->dbname());
        }
        [$host, $port] = $this->hostAndPort($settings);

        return sprintf('mysql:host=%s;%sdbname=%s;charset=utf8mb4', $host, $port === null ? '' : 'port=' . $port . ';', $settings->dbname());
    }

    /**
     * The host and the port, the port taken from a `host:port` value when it is not configured apart.
     *
     * @return array{0: string, 1: int|null}
     */
    private function hostAndPort(DatabaseSettings $settings): array
    {
        $host = $settings->host();
        $port = $settings->port();
        if ($port === null && preg_match(self::HOST_WITH_PORT, $host, $parts) === 1) {
            return [trim($parts['host'], '[]'), (int) $parts['port']];
        }

        return [trim($host, '[]'), $port];
    }

    private function where(DatabaseSettings $settings): string
    {
        $socket = $settings->socket();
        if ($socket !== null && $socket !== '') {
            return 'the socket ' . $socket;
        }
        [$host, $port] = $this->hostAndPort($settings);

        return $port === null ? $host : $host . ':' . $port;
    }

    private function errorCode(\PDOException $exception): string
    {
        $driverCode = $exception->errorInfo[1] ?? null;
        if (is_int($driverCode)) {
            return (string) $driverCode;
        }
        // On a failed connect the driver code is only in the message: `SQLSTATE[HY000] [2002] …`.
        if (preg_match('/\[(\d{4})\]/', $exception->getMessage(), $match) === 1) {
            return $match[1];
        }

        return (string) $exception->getCode();
    }
}
