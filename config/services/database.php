<?php

declare(strict_types=1);

use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\JournalSchema;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ReencryptionWriter;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\BatchedJournalPurger;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\InformationSchemaColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JitteredRetryPause;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\JournalTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\KeysetCiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RetryPause;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\RunRegistryTable;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalJournalReverter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TransactionalReencryptionWriter;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;

/*
 * The database adapters: discovery, paging, the compare-and-swap writer, the journal and the store's
 * claim of the run that may change its keys. They share one
 * connection per process (PdoConnectionProvider, a shared service), opened on first use.
 *
 * CronScheduleActivity is a WorkerActivity source of its own; it is composed with the other sources
 * where the WorkerActivity port is bound, not aliased here.
 */
return static function (ContainerConfigurator $container): void {
    $services = $container->services()
        ->defaults()
        ->autowire()
        ->autoconfigure()
        ->private();

    $services->alias(EncryptedColumnFinder::class, InformationSchemaColumnFinder::class);
    $services->alias(CiphertextRows::class, KeysetCiphertextRows::class);
    $services->alias(ReencryptionWriter::class, TransactionalReencryptionWriter::class);
    $services->alias(JournalReverter::class, TransactionalJournalReverter::class);
    $services->alias(JournalPurger::class, BatchedJournalPurger::class);
    $services->alias(JournalSchema::class, JournalTable::class);
    $services->alias(RetryPause::class, JitteredRetryPause::class);
    $services->alias(RunRegistry::class, RunRegistryTable::class);
};
