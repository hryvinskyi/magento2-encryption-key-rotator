<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\RecordingProgress;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DatabaseAdapters;
use Symfony\Component\Clock\MockClock;

/**
 * The cron schedule as a source of running workers: running jobs started within the last 15 minutes,
 * by the injected clock, with their start time; nothing when the store has no schedule; an unknown
 * start when the schedule cannot be read.
 */
final class CronScheduleActivityTest extends DatabaseTestCase
{
    private const NOW = '2026-10-29 12:00:00';

    protected function adapters(): DatabaseAdapters
    {
        return new DatabaseAdapters($this->database->deploymentConfig(), new RecordingProgress(), new MockClock(self::NOW . ' UTC'));
    }

    public function testRunningJobsOfTheLastFifteenMinutesAreReportedWithTheirStart(): void
    {
        $this->database->exec(sprintf(
            'CREATE TABLE `%s` (schedule_id INT UNSIGNED NOT NULL AUTO_INCREMENT PRIMARY KEY, job_code VARCHAR(255) NOT NULL,'
            . ' status VARCHAR(7) NOT NULL, executed_at TIMESTAMP NULL)',
            $this->database->table('cron_schedule'),
        ));
        foreach ([
            ['indexer_reindex_all_invalid', 'running', '2026-10-29 11:58:30'],
            ['sales_clean_quotes', 'running', '2026-10-29 11:45:00'],
            ['catalog_import', 'running', '2026-10-29 11:44:59'],
            ['newsletter_send_all', 'success', '2026-10-29 11:59:00'],
            ['consumers_runner', 'pending', null],
        ] as [$code, $status, $executedAt]) {
            $this->database->connection()->prepare(sprintf('INSERT INTO `%s` (job_code, status, executed_at) VALUES (?, ?, ?)', $this->database->table('cron_schedule')))
                ->execute([$code, $status, $executedAt]);
        }

        $running = $this->adapters->cron->running();

        self::assertSame([
            ['sales_clean_quotes', '2026-10-29T11:45:00+00:00'],
            ['indexer_reindex_all_invalid', '2026-10-29T11:58:30+00:00'],
        ], array_map(static fn(RunningProcess $process): array => [$process->description(), $process->startedAt()?->format(DATE_ATOM)], $running));
    }

    public function testAStoreWithoutACronScheduleRunsNoJobs(): void
    {
        self::assertSame([], $this->adapters->cron->running());
    }

    public function testAScheduleThatCannotBeReadIsAProcessOfUnknownStart(): void
    {
        $this->database->exec(sprintf('CREATE TABLE `%s` (schedule_id INT NOT NULL PRIMARY KEY)', $this->database->table('cron_schedule')));

        $running = $this->adapters->cron->running();

        self::assertCount(1, $running);
        self::assertNull($running[0]->startedAt());
        self::assertStringContainsString('could not be read', $running[0]->description());
    }
}
