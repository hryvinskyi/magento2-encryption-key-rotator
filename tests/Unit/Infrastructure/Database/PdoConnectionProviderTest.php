<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DatabaseUnavailable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoConnectionProvider;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\RecordingPdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * The connection is asked for exactly as the deployment configuration names it, with strict
 * attributes, and a failed connect never passes the driver's message, which may carry the login, on.
 */
final class PdoConnectionProviderTest extends TestCase
{
    private const PASSWORD = 'Password-That-Must-Not-Leak-91c2';

    /**
     * @return iterable<string, array{DatabaseSettings, string, string}>
     */
    public static function addresses(): iterable
    {
        yield 'host and port apart' => [self::settings('db.internal', 3307, null), 'mysql:host=db.internal;port=3307;dbname=store;charset=utf8mb4', 'db.internal:3307'];
        yield 'host carrying its port' => [self::settings('db.internal:3308', null, null), 'mysql:host=db.internal;port=3308;dbname=store;charset=utf8mb4', 'db.internal:3308'];
        yield 'host without a port' => [self::settings('localhost', null, null), 'mysql:host=localhost;dbname=store;charset=utf8mb4', 'localhost'];
        yield 'bracketed IPv6 with a port' => [self::settings('[::1]:3306', null, null), 'mysql:host=::1;port=3306;dbname=store;charset=utf8mb4', '::1:3306'];
        yield 'bare IPv6' => [self::settings('::1', null, null), 'mysql:host=::1;dbname=store;charset=utf8mb4', '::1'];
        yield 'unix socket' => [self::settings('localhost', null, '/run/mysqld/mysqld.sock'), 'mysql:unix_socket=/run/mysqld/mysqld.sock;dbname=store;charset=utf8mb4', 'the socket /run/mysqld/mysqld.sock'];
    }

    #[DataProvider('addresses')]
    public function testTheConnectionIsAskedForAsConfiguredAndAFailureNamesOnlyThePlace(DatabaseSettings $settings, string $dsn, string $where): void
    {
        $pdos = new RecordingPdoFactory();
        $provider = new PdoConnectionProvider($this->config($settings), $pdos);

        try {
            $provider->connection();
            self::fail('The factory refuses every connection.');
        } catch (DatabaseUnavailable $exception) {
            self::assertSame(sprintf('Cannot connect to the database "store" on %s (error 1045).', $where), $exception->getMessage());
            self::assertStringNotContainsString(self::PASSWORD, $exception->getMessage());
            self::assertNull($exception->getPrevious(), 'The driver exception, whose trace holds the login, is not chained.');
        }

        self::assertSame([[
            'dsn' => $dsn,
            'username' => 'store_user',
            'options' => [
                \PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION,
                \PDO::ATTR_EMULATE_PREPARES => false,
                \PDO::ATTR_STRINGIFY_FETCHES => false,
                \PDO::ATTR_TIMEOUT => 10,
            ],
        ]], $pdos->calls());
    }

    public function testTheTablePrefixComesFromTheSettingsWithoutConnecting(): void
    {
        $pdos = new RecordingPdoFactory();
        $provider = new PdoConnectionProvider($this->config(self::settings('db', null, null)), $pdos);

        self::assertSame('m2_', $provider->tablePrefix());
        self::assertSame([], $pdos->calls());
    }

    private static function settings(string $host, ?int $port, ?string $socket): DatabaseSettings
    {
        return new DatabaseSettings($host, $port, $socket, 'store', 'store_user', self::PASSWORD, 'm2_', '');
    }

    private function config(DatabaseSettings $settings): InMemoryDeploymentConfig
    {
        return new InMemoryDeploymentConfig(CryptoServices::shared()->ringParser()->parse(KeyMaterial::base64Key()), databaseSettings: $settings);
    }
}
