<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunClaimedElsewhere;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableNames;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\RunRegistryContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TestDatabase;

/**
 * The store's table keeps the run registry contract on a real server, under a table prefix, with the
 * second process on a connection of its own.
 */
final class DatabaseRunRegistryTest extends RunRegistryContractTestCase
{
    private TestDatabase $database;

    private DatabaseAdapters $adapters;

    private DatabaseAdapters $other;

    protected function setUp(): void
    {
        $this->database = TestDatabase::create('rr_');
        $this->adapters = new DatabaseAdapters($this->database->deploymentConfig());
        $this->other = new DatabaseAdapters($this->database->deploymentConfig());
    }

    protected function tearDown(): void
    {
        $this->database->drop();
    }

    public function testTheFirstClaimCreatesThePrefixedTableWithOneRow(): void
    {
        $table = $this->database->table(TableNames::RUN_REGISTRY);
        self::assertEquals(0, $this->database->value('SELECT COUNT(*) FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?', [$table]));

        $this->registry()->claim(new RunId(str_repeat('c', 32)), '/state');

        self::assertEquals(1, $this->database->value(sprintf('SELECT COUNT(*) FROM `%s`', $table)));
        self::assertNotNull($this->database->value(sprintf('SELECT claimed_at FROM `%s`', $table)));
    }

    public function testTheTableIsNotACandidateForTheScan(): void
    {
        $this->registry()->claim(new RunId(str_repeat('c', 32)), '/state/' . str_repeat('directory/', 10));

        $tables = array_map(
            static fn(ColumnCandidate $candidate): string => $candidate->column()->table(),
            $this->adapters->finder->candidates(new ScanScope([])),
        );

        self::assertNotContains(TableNames::RUN_REGISTRY, $tables);
    }

    public function testTheStoreHoldsOneClaimAtReadCommittedToo(): void
    {
        $isolation = 'SET SESSION TRANSACTION ISOLATION LEVEL READ COMMITTED';
        $first = new DatabaseAdapters($this->database->deploymentConfig($isolation));
        $second = new DatabaseAdapters($this->database->deploymentConfig($isolation));
        $first->registry->claim(new RunId(str_repeat('a', 32)), '/state/a');

        try {
            $second->registry->claim(new RunId(str_repeat('b', 32)), '/state/b');
            self::fail('A second run claimed the store.');
        } catch (RunClaimedElsewhere $refused) {
            self::assertSame(str_repeat('a', 32), $refused->runId());
        }

        $this->expectException(\PDOException::class);
        $this->database->connection()->exec(sprintf(
            "INSERT INTO `%s` (claim_slot, run_id, state_directory, claimed_at) VALUES (1, '%s', '/state/b', UTC_TIMESTAMP())",
            $this->database->table(TableNames::RUN_REGISTRY),
            str_repeat('b', 32),
        ));
    }

    protected function registry(): RunRegistry
    {
        return $this->adapters->registry;
    }

    protected function otherProcess(): RunRegistry
    {
        return $this->other->registry;
    }
}
