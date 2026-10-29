<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DatabaseUnavailable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoConnectionProvider;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;

/**
 * One connection per process, opened as configured: the init statements run, the SQL mode and the
 * isolation level stay the server's, numbers come back as numbers, and a refused login names the place
 * without the password.
 */
final class PdoConnectionProviderTest extends DatabaseTestCase
{
    public function testTheConnectionRunsTheInitStatementsAndKeepsTheServersModeAndIsolation(): void
    {
        $provider = new PdoConnectionProvider($this->database->deploymentConfig('SET @configured_marker = \'set\'; SET SESSION wait_timeout = 1234;'), new DirectPdoFactory());
        $connection = $provider->connection();
        $isolation = $this->database->isMysql() ? 'transaction_isolation' : 'tx_isolation';

        $statement = $connection->prepare(sprintf(
            'SELECT @configured_marker AS marker, @@SESSION.wait_timeout AS wait_timeout, @@SESSION.sql_mode = @@GLOBAL.sql_mode AS same_mode,'
            . ' @@SESSION.%1$s = @@GLOBAL.%1$s AS same_isolation, @@SESSION.%1$s AS isolation, 7 AS number',
            $isolation,
        ));
        $statement->execute();
        $session = $statement->fetch(\PDO::FETCH_ASSOC);

        self::assertSame(['marker' => 'set', 'wait_timeout' => 1234, 'same_mode' => 1, 'same_isolation' => 1, 'isolation' => 'REPEATABLE-READ', 'number' => 7], $session);
        self::assertSame($connection, $provider->connection(), 'One connection per process.');
        self::assertSame(\PDO::ERRMODE_EXCEPTION, $connection->getAttribute(\PDO::ATTR_ERRMODE));
        self::assertFalse((bool) $connection->getAttribute(\PDO::ATTR_EMULATE_PREPARES), 'Statements are prepared on the server.');
    }

    public function testAHostCarryingItsPortConnects(): void
    {
        $settings = $this->database->settings();
        $provider = new PdoConnectionProvider($this->config(new DatabaseSettings(
            $settings->host() . ':3306',
            null,
            null,
            $settings->dbname(),
            $settings->user(),
            $settings->password(),
            '',
            '',
        )), new DirectPdoFactory());

        $statement = $provider->connection()->prepare('SELECT DATABASE()');
        $statement->execute();

        self::assertSame($settings->dbname(), $statement->fetchColumn());
    }

    public function testARefusedLoginNamesTheHostAndDatabaseButNeverThePassword(): void
    {
        $settings = $this->database->settings();
        $password = 'Wrong-Password-That-Must-Not-Leak-' . bin2hex(random_bytes(4));
        $provider = new PdoConnectionProvider($this->config(new DatabaseSettings(
            $settings->host(),
            3306,
            null,
            $settings->dbname(),
            $settings->user(),
            $password,
            '',
            '',
        )), new DirectPdoFactory());

        try {
            $provider->connection();
            self::fail('A wrong password is refused.');
        } catch (DatabaseUnavailable $exception) {
            self::assertSame(sprintf('Cannot connect to the database "%s" on %s:3306 (error 1045).', $settings->dbname(), $settings->host()), $exception->getMessage());
            self::assertStringNotContainsString($password, $exception->getMessage() . $exception->getTraceAsString());
        }
    }

    public function testRefusedInitStatementsMakeTheDatabaseUnavailable(): void
    {
        $provider = new PdoConnectionProvider($this->database->deploymentConfig('SET SESSION no_such_variable = 1'), new DirectPdoFactory());

        $this->expectException(DatabaseUnavailable::class);
        $this->expectExceptionMessage('refused the configured init statements');

        $provider->connection();
    }

    private function config(DatabaseSettings $settings): InMemoryDeploymentConfig
    {
        return new InMemoryDeploymentConfig(CryptoServices::shared()->ringParser()->parse(KeyMaterial::base64Key()), databaseSettings: $settings);
    }
}
