<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Reencryption;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\BatchedJournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\CronScheduleActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\InformationSchemaColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JournalTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\KeysetCiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RunRegistryTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalJournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseWiring;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TestDatabase;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The real container binds every database port to its adapter, generates the connection factory over
 * `\PDO`, and the adapters it builds share one connection that finds, writes, journals and undoes.
 */
final class DatabaseWiringTest extends TestCase
{
    private TestDatabase $database;

    private string $buildDirectory;

    protected function setUp(): void
    {
        $this->database = TestDatabase::create('m2_');
        DatabaseWiring::use($this->database->deploymentConfig());
        $this->buildDirectory = TemporaryDirectory::create('key-rotator-database-wiring');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->buildDirectory);
        $this->database->drop();
    }

    public function testThePortsResolveToTheDatabaseAdaptersAndWorkTogether(): void
    {
        $container = $this->container();
        $this->database->exec(sprintf('CREATE TABLE `%s` (entity_id INT NOT NULL PRIMARY KEY, secret VARCHAR(128) NOT NULL)', $this->database->table('oauth_consumer')));
        $old = new Ciphertext(0, 3, base64_encode(str_repeat('o', 48)));
        $new = new Ciphertext(1, 3, base64_encode(str_repeat('n', 48)));
        $this->database->exec(sprintf('INSERT INTO `%s` VALUES (1, \'%s\')', $this->database->table('oauth_consumer'), $old->toString()));
        $column = new ColumnRef('oauth_consumer', 'secret');

        $finder = $this->get($container, EncryptedColumnFinder::class);
        $rows = $this->get($container, CiphertextRows::class);
        $schema = $this->get($container, JournalSchema::class);
        $writer = $this->get($container, ReencryptionWriter::class);
        $reverter = $this->get($container, JournalReverter::class);
        $purger = $this->get($container, JournalPurger::class);

        self::assertInstanceOf(InformationSchemaColumnFinder::class, $finder);
        self::assertInstanceOf(KeysetCiphertextRows::class, $rows);
        self::assertInstanceOf(JournalTable::class, $schema);
        self::assertInstanceOf(TransactionalReencryptionWriter::class, $writer);
        self::assertInstanceOf(TransactionalJournalReverter::class, $reverter);
        self::assertInstanceOf(BatchedJournalPurger::class, $purger);
        self::assertSame([], $this->get($container, CronScheduleActivity::class)->running());

        self::assertSame([0 => 1], $finder->candidates(new ScanScope([]))[0]->shapeCounts());
        $schema->ensure();
        $read = null;
        foreach ($rows->batches($column, 0, 10) as $batch) {
            $read = $batch[0];
        }
        self::assertNotNull($read);
        self::assertSame(1, $writer->apply(new RunId(str_repeat('a', 32)), Direction::Forward, [new Reencryption($column, $read->rowKey(), $read->raw(), $new)])->applied());
        $pending = [];
        foreach ($reverter->pending(new RunId(str_repeat('a', 32))) as $batch) {
            $pending = [...$pending, ...$batch];
        }
        self::assertSame(1, $reverter->revert($pending)->applied());
        self::assertSame($old->toString(), $this->database->value(sprintf('SELECT secret FROM `%s` WHERE entity_id = 1', $this->database->table('oauth_consumer'))));
        self::assertSame(1, $purger->purge(new RunId(str_repeat('a', 32))));
        self::assertEquals(new RowKey(['entity_id' => 1]), $read->rowKey());
    }

    public function testTheRunRegistryResolvesToTheStoresTable(): void
    {
        $registry = $this->get($this->container(), RunRegistry::class);
        self::assertInstanceOf(RunRegistryTable::class, $registry);

        $registry->claim(new RunId(str_repeat('a', 32)), '/state');

        self::assertSame(['run_id' => str_repeat('a', 32), 'state_directory' => '/state'], $registry->claimed());
    }

    public function testTheGeneratedConnectionFactoryCreatesPdoConnections(): void
    {
        $settings = $this->database->settings();

        $connection = $this->get($this->container(), PdoFactory::class)->create(
            sprintf('mysql:host=%s;port=3306;dbname=%s', $settings->host(), $settings->dbname()),
            $settings->user(),
            $settings->password(),
            [\PDO::ATTR_ERRMODE => \PDO::ERRMODE_EXCEPTION],
        );

        $statement = $connection->prepare('SELECT DATABASE()');
        $statement->execute();

        self::assertSame($settings->dbname(), $statement->fetchColumn());
    }

    private function container(): ContainerInterface
    {
        $root = dirname(__DIR__, 3);

        return (new ContainerFactory(
            $root . '/tests/Fixtures/Container/database-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile($this->buildDirectory);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    private function get(ContainerInterface $container, string $id): object
    {
        $service = $container->get('test.' . $id);
        if (!$service instanceof $id) {
            throw new \LogicException(sprintf('The container holds no %s.', $id));
        }

        return $service;
    }
}
