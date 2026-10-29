<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * How to reach the store's database, as the deployment configuration names it: a host (with a port) or
 * a socket, the database, the user and password, the table prefix every table name carries, and the
 * statements to run on every new connection.
 *
 * The password never prints itself: it is left out of a dump, and serialising the settings fails.
 * Created through {@see DatabaseSettingsFactory}.
 */
final class DatabaseSettings
{
    /**
     * @param string      $host           host name or address, as configured (it may carry `:port`)
     * @param int|null    $port           the port, when configured apart from the host
     * @param string|null $socket         the unix socket path, when the connection goes through one
     * @param string      $dbname         the database
     * @param string      $user           the user
     * @param string      $password       the user's password
     * @param string      $tablePrefix    the prefix of every table name, possibly empty
     * @param string      $initStatements the statements run on every new connection, as configured, possibly empty
     *
     * @throws InvalidValue when no database or user is named, or the port is out of range
     */
    public function __construct(
        private readonly string $host,
        private readonly ?int $port,
        private readonly ?string $socket,
        private readonly string $dbname,
        private readonly string $user,
        #[\SensitiveParameter]
        private readonly string $password,
        private readonly string $tablePrefix,
        private readonly string $initStatements,
    ) {
        if ($dbname === '' || $user === '') {
            throw new InvalidValue('Database settings name a database and a user.');
        }
        if ($host === '' && ($socket === null || $socket === '')) {
            throw new InvalidValue('Database settings name a host or a socket.');
        }
        if ($port !== null && ($port < 1 || $port > 65535)) {
            throw new InvalidValue(sprintf('A database port lies between 1 and 65535; %d was given.', $port));
        }
    }

    public function host(): string
    {
        return $this->host;
    }

    public function port(): ?int
    {
        return $this->port;
    }

    public function socket(): ?string
    {
        return $this->socket;
    }

    public function dbname(): string
    {
        return $this->dbname;
    }

    public function user(): string
    {
        return $this->user;
    }

    public function password(): string
    {
        return $this->password;
    }

    public function tablePrefix(): string
    {
        return $this->tablePrefix;
    }

    public function initStatements(): string
    {
        return $this->initStatements;
    }

    /**
     * @return array{host: string, port: int|null, socket: string|null, dbname: string, user: string, password: string, tablePrefix: string, initStatements: string}
     */
    public function __debugInfo(): array
    {
        return [
            'host' => $this->host,
            'port' => $this->port,
            'socket' => $this->socket,
            'dbname' => $this->dbname,
            'user' => $this->user,
            'password' => '[redacted]',
            'tablePrefix' => $this->tablePrefix,
            'initStatements' => $this->initStatements,
        ];
    }

    /**
     * @return array<string, mixed>
     *
     * @throws \LogicException always: the settings hold a password, which is never serialised
     */
    public function __serialize(): array
    {
        throw new \LogicException('Database settings cannot be serialised.');
    }

    /**
     * @param array<string, mixed> $data
     *
     * @throws \LogicException always: settings are never restored from serialised data
     */
    public function __unserialize(array $data): void
    {
        throw new \LogicException('Database settings cannot be unserialised.');
    }
}
