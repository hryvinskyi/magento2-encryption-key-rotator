<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Runs work in one transaction: commit when it returns, roll back and rethrow when it throws.
 *
 * A transaction the server aborted for a deadlock or a lock wait timeout (SQLSTATE 40001, MySQL errors
 * 1213 and 1205) is rolled back and run again from the start, up to three more times, after a jittered
 * pause. The work must therefore build its whole result inside the transaction. This is the only place
 * the tool retries a database write.
 */
final class TransactionRunner
{
    private const RETRIES = 3;
    private const DEADLOCK = 1213;
    private const LOCK_WAIT_TIMEOUT = 1205;
    private const SERIALIZATION_FAILURE = '40001';

    public function __construct(
        private readonly PdoConnectionProvider $database,
        private readonly RetryPause $pause,
    ) {}

    /**
     * @template T
     *
     * @param \Closure(): T $work
     *
     * @return T
     *
     * @throws \Throwable what the work or the commit threw, once no retry is left
     */
    public function run(\Closure $work): mixed
    {
        $connection = $this->database->connection();
        for ($attempt = 1; ; $attempt++) {
            $connection->beginTransaction();
            try {
                $result = $work();
                $connection->commit();

                return $result;
            } catch (\Throwable $failure) {
                $this->rollBack($connection);
                if ($attempt > self::RETRIES || !$this->isTransient($failure)) {
                    throw $failure;
                }
                $this->pause->after($attempt);
            }
        }
    }

    private function rollBack(\PDO $connection): void
    {
        if (!$connection->inTransaction()) {
            return;
        }
        try {
            $connection->rollBack();
        } catch (\PDOException) {
            // The failure that led here is the one worth reporting; the server ends the transaction anyway.
        }
    }

    private function isTransient(\Throwable $failure): bool
    {
        if (!$failure instanceof \PDOException) {
            return false;
        }
        $info = $failure->errorInfo ?? [];

        return ($info[0] ?? null) === self::SERIALIZATION_FAILURE
            || in_array($info[1] ?? null, [self::DEADLOCK, self::LOCK_WAIT_TIMEOUT], true);
    }
}
