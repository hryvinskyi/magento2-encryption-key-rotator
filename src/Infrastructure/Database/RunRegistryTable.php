<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunClaimedElsewhere;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The store's claim, in `<prefix>encryption_key_rotation_run`: at most one row, the run that holds the
 * store (`run_id`), where it keeps its files (`state_directory`) and when it claimed it (`claimed_at`).
 *
 * The table is created by the first claim. Its primary key is a single fixed slot, so the table can hold
 * one claim whatever isolation level the server runs at: a claim inserts into that slot first, and only
 * when the slot is taken reads who holds it (a locking read, which sees the latest committed row). Two
 * runs claiming at once from different state directories meet on that key; the second waits for the
 * first to commit, gets the duplicate, and is refused with the holder named. A release deletes the
 * run's row and leaves the table; dropping it could take away the row of a claim that is committing at
 * that moment.
 */
final class RunRegistryTable implements RunRegistry
{
    private const CLAIM_SLOT = 1;
    private const DUPLICATE_KEY = 1062;

    public function __construct(
        private readonly Statements $statements,
        private readonly TableNames $names,
        private readonly FetchedValues $values,
        private readonly TransactionRunner $transactions,
    ) {}

    public function claim(RunId $id, string $stateDirectory): void
    {
        $this->ensure();
        $this->transactions->run(function () use ($id, $stateDirectory): void {
            // A holder that releases between the duplicate and the read leaves the slot free: insert again.
            while (!$this->insertClaim($id, $stateDirectory)) {
                $rows = $this->values->all($this->statements->run(
                    sprintf('SELECT run_id, state_directory FROM %s WHERE claim_slot = ? FOR UPDATE', $this->names->runRegistry()),
                    [self::CLAIM_SLOT],
                ));
                if ($rows === []) {
                    continue;
                }
                $holder = $this->values->string($rows[0], 'run_id');
                if ($holder !== $id->toString()) {
                    throw new RunClaimedElsewhere($holder, $this->values->string($rows[0], 'state_directory'));
                }

                return;
            }
        });
    }

    public function claimed(): ?array
    {
        if (!$this->exists()) {
            return null;
        }
        $rows = $this->values->all($this->statements->run(sprintf(
            'SELECT run_id, state_directory FROM %s',
            $this->names->runRegistry(),
        )));
        if ($rows === []) {
            return null;
        }

        return [
            'run_id' => $this->values->string($rows[0], 'run_id'),
            'state_directory' => $this->values->string($rows[0], 'state_directory'),
        ];
    }

    public function release(RunId $id): void
    {
        if (!$this->exists()) {
            return;
        }
        $this->statements->run(sprintf('DELETE FROM %s WHERE run_id = ?', $this->names->runRegistry()), [$id->toString()]);
    }

    /**
     * Inserts the claim into the slot; false when the slot is already taken.
     *
     * @throws \PDOException on any failure but the taken slot
     */
    private function insertClaim(RunId $id, string $stateDirectory): bool
    {
        try {
            $this->statements->run(
                sprintf(
                    'INSERT INTO %s (claim_slot, run_id, state_directory, claimed_at) VALUES (?, ?, ?, UTC_TIMESTAMP())',
                    $this->names->runRegistry(),
                ),
                [self::CLAIM_SLOT, $id->toString(), $stateDirectory],
            );
        } catch (\PDOException $taken) {
            if (($taken->errorInfo[1] ?? null) !== self::DUPLICATE_KEY) {
                throw $taken;
            }

            return false;
        }

        return true;
    }

    private function ensure(): void
    {
        $this->statements->define(sprintf(
            'CREATE TABLE IF NOT EXISTS %s ('
            . 'claim_slot TINYINT UNSIGNED NOT NULL PRIMARY KEY,'
            . ' run_id CHAR(32) NOT NULL,'
            . ' state_directory TEXT NOT NULL,'
            . ' claimed_at DATETIME NOT NULL'
            . ') ENGINE=InnoDB DEFAULT CHARSET=utf8mb4',
            $this->names->runRegistry(),
        ));
    }

    private function exists(): bool
    {
        $rows = $this->values->all($this->statements->run(
            'SELECT COUNT(*) AS tables_count FROM information_schema.TABLES WHERE TABLE_SCHEMA = DATABASE() AND TABLE_NAME = ?',
            [$this->names->physical(TableNames::RUN_REGISTRY)],
        ));

        return $this->values->int($rows[0] ?? [], 'tables_count') > 0;
    }
}
