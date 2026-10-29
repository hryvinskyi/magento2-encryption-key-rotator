<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\BatchedJournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\CiphertextPatterns;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\CompareAndSwap;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\CronScheduleActivity;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\FetchedValues;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\InformationSchemaColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JournalRows;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JournalTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\KeysetCiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoConnectionProvider;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RetryPause;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RowKeySql;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RunRegistryTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\ShapeCounter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\Statements;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableNames;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableStructure;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalJournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionRunner;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectColumnCandidateFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectColumnRefFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectConflictFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectDateTimeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectJournalEntryFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectPdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRowKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectRunningProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectStoredValueFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectWriteResultFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\ScriptedRetryPause;
use Psr\Clock\ClockInterface;
use Symfony\Component\Clock\NativeClock;

/**
 * The database adapters wired by hand over one connection, as the container wires them, with test
 * doubles where a test needs to watch or steer: the progress output, the clock, the pause before a
 * retry and the journal's batch size.
 */
final class DatabaseAdapters
{
    public readonly PdoConnectionProvider $connection;
    public readonly TableNames $names;
    public readonly TableStructure $structure;
    public readonly InformationSchemaColumnFinder $finder;
    public readonly KeysetCiphertextRows $rows;
    public readonly TransactionalReencryptionWriter $writer;
    public readonly TransactionalJournalReverter $reverter;
    public readonly BatchedJournalPurger $purger;
    public readonly JournalTable $schema;
    public readonly CronScheduleActivity $cron;
    public readonly RunRegistryTable $registry;

    public function __construct(
        DeploymentConfigReader $deploymentConfig,
        public readonly Progress $progress = new RecordingProgress(),
        ClockInterface $clock = new NativeClock(),
        RetryPause $pause = new ScriptedRetryPause(),
        int $journalBatchSize = 500,
    ) {
        $this->connection = new PdoConnectionProvider($deploymentConfig, new DirectPdoFactory());
        $statements = new Statements($this->connection);
        $values = new FetchedValues();
        $this->names = new TableNames($this->connection);
        $this->structure = new TableStructure($statements, $this->names, $values);
        $rowKeySql = new RowKeySql($this->names, $values, new DirectRowKeyFactory());
        $this->finder = new InformationSchemaColumnFinder(
            $this->names,
            $this->structure,
            new ShapeCounter($statements, $this->names, $this->structure, $values),
            $values,
            $statements,
            new DirectColumnRefFactory(),
            new DirectColumnCandidateFactory(),
            $progress,
            $clock,
        );
        $this->rows = new KeysetCiphertextRows($statements, $this->names, $this->structure, $rowKeySql, new CiphertextPatterns(), $values, new DirectStoredValueFactory());
        $transactions = new TransactionRunner($this->connection, $pause);
        $compareAndSwap = new CompareAndSwap($statements, $this->names, $this->structure, $rowKeySql, $values, new DirectConflictFactory());
        $journal = new JournalRows($statements, $this->names, $values, new DirectColumnRefFactory(), new DirectRowKeyFactory(), new DirectJournalEntryFactory());
        $this->writer = new TransactionalReencryptionWriter($transactions, $compareAndSwap, $journal, new DirectWriteResultFactory());
        $this->reverter = new TransactionalJournalReverter($transactions, $compareAndSwap, $journal, new DirectWriteResultFactory(), $journalBatchSize);
        $this->schema = new JournalTable($statements, $this->names, $values);
        $this->purger = new BatchedJournalPurger($statements, $this->names, $this->schema);
        $this->registry = new RunRegistryTable($statements, $this->names, $values, $transactions);
        $this->cron = new CronScheduleActivity($statements, $this->names, $this->structure, $values, new DirectRunningProcessFactory(), new DirectDateTimeFactory(), $clock);
    }
}
