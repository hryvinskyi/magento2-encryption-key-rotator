<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;

/**
 * Lists the store's processes that hold the key ring they started with: cron runs, queue consumers and
 * long commands, the web tier excluded. When they cannot be listed, the result holds one entry with an
 * unknown start time, so "none" and "unknown" are never confused.
 */
interface WorkerActivity
{
    /**
     * @return list<RunningProcess>
     */
    public function running(): array;
}
