<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;

/**
 * Reads what the tool needs out of an evaluated configuration array: the key ring of `crypt/key`, the
 * default database connection with the table prefix, and the ciphertexts of the `system` section.
 *
 * A failure names the file and the section, never a value.
 */
final class DeploymentConfigMapper
{
    public const CRYPT_KEY = ['crypt', 'key'];
    public const SYSTEM = 'system';

    private const CONNECTION = ['db', 'connection', 'default'];
    private const TABLE_PREFIX = ['db', 'table_prefix'];
    private const HOST_WITH_PORT = '/^([^:]+):([0-9]{1,5})$/D';

    public function __construct(
        private readonly NestedArray $tree,
        private readonly KeyRingParser $rings,
        private readonly CiphertextParser $ciphertexts,
        private readonly SystemValueFactory $systemValues,
        private readonly DatabaseSettingsFactory $databaseSettings,
    ) {}

    /**
     * @param array<mixed> $config the evaluated file
     * @param string       $file   the file's path, for messages
     *
     * @throws DeploymentConfigUnreadable when the file holds no `crypt/key` string
     * @throws InvalidKeyRing             when the entries do not form a key ring
     * @throws InvalidKey                 when an entry that is not a placeholder is not a usable key
     */
    public function keyRing(array $config, string $file): KeyRing
    {
        $cryptKey = $this->tree->get($config, self::CRYPT_KEY);
        if (!is_string($cryptKey)) {
            throw new DeploymentConfigUnreadable(sprintf('%s holds no crypt/key.', $file));
        }

        return $this->rings->parse($cryptKey);
    }

    /**
     * The default connection as the store connects with it: a host holding a `/` is the path of a unix
     * socket, and a host of the form `name:port` carries the port.
     *
     * @param array<mixed> $config the evaluated file
     * @param string       $file   the file's path, for messages
     *
     * @throws DeploymentConfigUnreadable when the file names no default connection, or a field of it does
     *                                    not hold what a connection needs
     */
    public function databaseSettings(array $config, string $file): DatabaseSettings
    {
        $connection = $this->tree->get($config, self::CONNECTION);
        if (!is_array($connection)) {
            throw new DeploymentConfigUnreadable(sprintf('%s names no db/connection/default.', $file));
        }

        [$host, $port, $socket] = $this->endpoint(
            $this->text($connection, 'host', $file) ?? '',
            $this->port($connection, $file),
            $this->text($connection, 'unix_socket', $file),
        );

        try {
            return $this->databaseSettings->create(
                host: $host,
                port: $port,
                socket: $socket,
                dbname: $this->text($connection, 'dbname', $file) ?? '',
                user: $this->text($connection, 'username', $file) ?? '',
                password: $this->text($connection, 'password', $file) ?? '',
                tablePrefix: $this->tablePrefix($config, $file),
                initStatements: $this->text($connection, 'initStatements', $file) ?? '',
            );
        } catch (InvalidValue $invalid) {
            throw new DeploymentConfigUnreadable(sprintf('db/connection/default of %s cannot be used: %s', $file, $invalid->getMessage()), 0, $invalid);
        }
    }

    /**
     * Every string of the `system` section that is a ciphertext, with the keys leading to it below
     * `system`.
     *
     * @param array<mixed> $config the evaluated file
     * @param string       $file   the file's path, for messages
     *
     * @return list<SystemValue>
     *
     * @throws DeploymentConfigUnreadable when `system` is not a section, or a ciphertext sits below an empty key
     */
    public function systemValues(array $config, SystemValueSource $source, string $file): array
    {
        $system = $config[self::SYSTEM] ?? null;
        if ($system === null) {
            return [];
        }
        if (!is_array($system)) {
            throw new DeploymentConfigUnreadable(sprintf('The system section of %s is not an array.', $file));
        }

        $values = [];
        $this->collect($system, [], $source, $file, $values);

        return $values;
    }

    /**
     * @param array<mixed>      $node
     * @param list<string>      $path
     * @param list<SystemValue> $values
     */
    private function collect(array $node, array $path, SystemValueSource $source, string $file, array &$values): void
    {
        foreach ($node as $key => $value) {
            $here = [...$path, (string) $key];
            if (is_array($value)) {
                $this->collect($value, $here, $source, $file, $values);

                continue;
            }
            if (!is_string($value)) {
                continue;
            }
            $ciphertext = $this->ciphertexts->parse($value);
            if ($ciphertext === null) {
                continue;
            }
            try {
                $values[] = $this->systemValues->create($here, $ciphertext, $source);
            } catch (InvalidValue $invalid) {
                throw new DeploymentConfigUnreadable(sprintf(
                    'A ciphertext of the system section of %s sits below an empty key: system/%s.',
                    $file,
                    implode('/', $here),
                ), 0, $invalid);
            }
        }
    }

    /**
     * Where the connection goes, read as the store reads its `host`: a path is the socket, and
     * `name:port` carries the port.
     *
     * @return array{string, int|null, string|null} the host, the port and the socket
     */
    private function endpoint(string $host, ?int $port, ?string $socket): array
    {
        if (str_contains($host, '/')) {
            return ['', $port, $host];
        }
        if (preg_match(self::HOST_WITH_PORT, $host, $parts) === 1) {
            return [$parts[1], (int) $parts[2], $socket];
        }

        return [$host, $port, $socket];
    }

    /**
     * @param array<mixed> $config
     */
    private function tablePrefix(array $config, string $file): string
    {
        $prefix = $this->tree->get($config, self::TABLE_PREFIX);
        if ($prefix === null || is_string($prefix)) {
            return $prefix ?? '';
        }

        throw new DeploymentConfigUnreadable(sprintf('db/table_prefix of %s is not a string.', $file));
    }

    /**
     * @param array<mixed> $connection
     */
    private function port(array $connection, string $file): ?int
    {
        $port = $connection['port'] ?? null;
        if ($port === null || $port === '') {
            return null;
        }
        if (is_int($port)) {
            return $port;
        }
        if (is_string($port) && ctype_digit($port)) {
            return (int) $port;
        }

        throw new DeploymentConfigUnreadable(sprintf('db/connection/default/port of %s is not a number.', $file));
    }

    /**
     * @param array<mixed> $connection
     */
    private function text(array $connection, string $field, string $file): ?string
    {
        $value = $connection[$field] ?? null;
        if ($value === null || is_string($value)) {
            return $value;
        }
        if (is_int($value)) {
            return (string) $value;
        }

        throw new DeploymentConfigUnreadable(sprintf('db/connection/default/%s of %s is not a string.', $field, $file));
    }
}
