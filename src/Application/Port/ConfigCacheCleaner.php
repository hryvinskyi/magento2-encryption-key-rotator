<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;

/**
 * Cleans the store's configuration cache, so the web tier reloads the configuration values the run
 * rewrote. A failure is an outcome, not an exception.
 */
interface ConfigCacheCleaner
{
    public function clean(): CacheCleanOutcome;
}
