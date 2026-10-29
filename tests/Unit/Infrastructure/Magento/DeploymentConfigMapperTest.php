<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigMapper;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\NestedArray;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectDatabaseSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\TestCase;

final class DeploymentConfigMapperTest extends TestCase
{
    private const FILE = '/store/app/etc/env.php';
    private const PASSWORD = 'Password-That-Must-Not-Leak-91c2';

    private DeploymentConfigMapper $mapper;

    protected function setUp(): void
    {
        $this->mapper = new DeploymentConfigMapper(
            new NestedArray(),
            new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory()),
            new CiphertextParser(new DirectCiphertextFactory()),
            new DirectSystemValueFactory(),
            new DirectDatabaseSettingsFactory(),
        );
    }

    public function testAHostWithAPortIsSplitAsTheStoreSplitsIt(): void
    {
        $settings = $this->mapper->databaseSettings($this->connection(['host' => 'db.internal:3307']), self::FILE);

        self::assertSame('db.internal', $settings->host());
        self::assertSame(3307, $settings->port());
        self::assertNull($settings->socket());
    }

    public function testAHostThatIsAPathIsTheSocket(): void
    {
        $settings = $this->mapper->databaseSettings($this->connection(['host' => '/run/mysqld/mysqld.sock']), self::FILE);

        self::assertSame('', $settings->host());
        self::assertSame('/run/mysqld/mysqld.sock', $settings->socket());
        self::assertNull($settings->port());
    }

    public function testASeparatePortAndSocketAreRead(): void
    {
        $settings = $this->mapper->databaseSettings($this->connection(['host' => 'db', 'port' => '3310', 'unix_socket' => '/tmp/db.sock']), self::FILE);

        self::assertSame('db', $settings->host());
        self::assertSame(3310, $settings->port());
        self::assertSame('/tmp/db.sock', $settings->socket());
    }

    public function testTheTablePrefixAndInitStatementsAreOptional(): void
    {
        $config = $this->connection([]);
        unset($config['db']['table_prefix'], $config['db']['connection']['default']['initStatements']);

        $settings = $this->mapper->databaseSettings($config, self::FILE);

        self::assertSame('', $settings->tablePrefix());
        self::assertSame('', $settings->initStatements());
        self::assertSame(self::PASSWORD, $settings->password());
    }

    public function testAMissingConnectionIsUnreadable(): void
    {
        $this->expectException(DeploymentConfigUnreadable::class);
        $this->expectExceptionMessage('db/connection/default');

        $this->mapper->databaseSettings(['db' => ['table_prefix' => '']], self::FILE);
    }

    public function testAnUnusableConnectionNamesTheFieldAndNeverThePassword(): void
    {
        try {
            $this->mapper->databaseSettings($this->connection(['dbname' => '']), self::FILE);
            self::fail('A connection without a database was accepted.');
        } catch (DeploymentConfigUnreadable $unreadable) {
            self::assertStringContainsString(self::FILE, $unreadable->getMessage());
            self::assertStringNotContainsString(self::PASSWORD, $unreadable->getMessage());
        }
    }

    public function testAPortThatIsNotANumberIsUnreadable(): void
    {
        $this->expectException(DeploymentConfigUnreadable::class);

        $this->mapper->databaseSettings($this->connection(['port' => 'mysql']), self::FILE);
    }

    public function testEveryCiphertextOfTheSystemSectionIsFoundWithItsPath(): void
    {
        $value = '1:3:' . base64_encode(str_repeat('v', 48));
        $other = '0:3:' . base64_encode(str_repeat('w', 48));

        $found = $this->mapper->systemValues([
            'system' => [
                'default' => ['payment' => ['gateway' => ['api_secret' => $value, 'mode' => 'live']]],
                'websites' => ['base' => ['carriers' => ['list' => [$other, 7, null, '1:3:not base64!']]]],
            ],
        ], SystemValueSource::Committed, self::FILE);

        self::assertSame(
            [['default/payment/gateway/api_secret', $value], ['websites/base/carriers/list/0', $other]],
            array_map(static fn(SystemValue $v): array => [$v->pathString(), $v->ciphertext()->toString()], $found),
        );
        self::assertSame(SystemValueSource::Committed, $found[0]->source());
    }

    public function testAFileWithoutASystemSectionHasNoSystemValues(): void
    {
        self::assertSame([], $this->mapper->systemValues(['crypt' => []], SystemValueSource::Env, self::FILE));
    }

    public function testTheRingComesFromCryptKey(): void
    {
        $ring = KeyMaterial::placeholder() . "\n" . KeyMaterial::base64Key();

        self::assertSame($ring, $this->mapper->keyRing(['crypt' => ['key' => $ring]], self::FILE)->export());
    }

    public function testAFileWithoutCryptKeyIsUnreadable(): void
    {
        $this->expectException(DeploymentConfigUnreadable::class);
        $this->expectExceptionMessage('crypt/key');

        $this->mapper->keyRing(['crypt' => ['invalidated_key' => 'x']], self::FILE);
    }

    /**
     * @param array<string, string> $overrides
     *
     * @return array{db: array{table_prefix: string, connection: array{default: array<string, string>}}}
     */
    private function connection(array $overrides): array
    {
        return ['db' => [
            'table_prefix' => 'm2_',
            'connection' => ['default' => array_replace([
                'host' => 'db',
                'dbname' => 'store',
                'username' => 'store',
                'password' => self::PASSWORD,
                'initStatements' => 'SET NAMES utf8;',
            ], $overrides)],
        ]];
    }
}
