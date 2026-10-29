<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\CacheCleanOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConfigCacheCleaner;

/**
 * A configuration cache cleaner that counts its calls and answers with queued outcomes, then with the
 * fallback (cleaned unless told otherwise).
 */
final class RecordingConfigCacheCleaner implements ConfigCacheCleaner
{
    /**
     * @var list<CacheCleanOutcome>
     */
    private array $queue;

    private int $calls = 0;

    /**
     * @param list<CacheCleanOutcome> $outcomes the answers of the first calls, in order
     */
    public function __construct(
        array $outcomes = [],
        private CacheCleanOutcome $fallback = new CacheCleanOutcome(true, ''),
        private readonly ?CallLog $log = null,
    ) {
        $this->queue = $outcomes;
    }

    public function clean(): CacheCleanOutcome
    {
        $this->calls++;
        $this->log?->record('cache.clean');

        return array_shift($this->queue) ?? $this->fallback;
    }

    /**
     * Changes the answer given once the queue is empty.
     */
    public function answerFromNowOn(CacheCleanOutcome $fallback): void
    {
        $this->fallback = $fallback;
    }

    public function calls(): int
    {
        return $this->calls;
    }
}
