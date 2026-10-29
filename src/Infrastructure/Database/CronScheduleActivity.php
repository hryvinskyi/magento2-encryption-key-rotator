<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcessFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DatabaseUnavailable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\DateTimeFactory;
use Psr\Clock\ClockInterface;

/**
 * The store's cron jobs the schedule says are running: rows of `cron_schedule` with the status
 * `running` that started within the last 15 minutes, each named by its job code and started at its
 * `executed_at`, which the store writes in UTC.
 *
 * A store without the table runs no cron jobs. A schedule that cannot be read yields one process with an
 * unknown start, so a failure is never taken for "nothing runs".
 */
final class CronScheduleActivity implements WorkerActivity
{
    private const TABLE = 'cron_schedule';
    private const WINDOW_SECONDS = 15 * 60;

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly TableStructure $structure,
        private readonly FetchedValues $values,
        private readonly RunningProcessFactory $processes,
        private readonly DateTimeFactory $moments,
        private readonly ClockInterface $clock,
    ) {}

    public function running(): array
    {
        try {
            if (!$this->structure->exists(self::TABLE)) {
                return [];
            }
            $rows = $this->values->all($this->statements->run(
                sprintf(
                    'SELECT job_code, executed_at FROM %s WHERE status = ? AND executed_at >= ? ORDER BY executed_at',
                    $this->names->table(self::TABLE),
                ),
                ['running', gmdate('Y-m-d H:i:s', $this->clock->now()->getTimestamp() - self::WINDOW_SECONDS)],
            ));
        } catch (DatabaseUnavailable|\PDOException $failure) {
            return [$this->processes->create(sprintf('cron jobs (the schedule could not be read: %s)', $this->reason($failure)), null)];
        }
        $processes = [];
        foreach ($rows as $row) {
            $processes[] = $this->processes->create(
                $this->values->string($row, 'job_code'),
                $this->moments->create($this->values->string($row, 'executed_at') . '+00:00'),
            );
        }

        return $processes;
    }

    private function reason(DatabaseUnavailable|\PDOException $failure): string
    {
        if ($failure instanceof DatabaseUnavailable) {
            return $failure->getMessage();
        }
        $code = $failure->errorInfo[1] ?? null;

        return 'database error ' . (is_int($code) ? (string) $code : (string) $failure->getCode());
    }
}
