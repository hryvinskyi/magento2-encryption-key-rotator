<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeStatus;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * A web tier probe that answers from a script: each call takes the next queued outcome, and once the
 * queue is empty every call gets the fallback (a match unless told otherwise). Every call records the
 * fingerprint of the ring it was asked about.
 */
final class ScriptedWebTierProbe implements WebTierProbe
{
    /**
     * @var list<ProbeOutcome>
     */
    private array $queue;

    /**
     * @var list<string>
     */
    private array $observed = [];

    /**
     * @param list<ProbeOutcome> $outcomes the answers of the first calls, in order
     */
    public function __construct(
        array $outcomes = [],
        private ProbeOutcome $fallback = new ProbeOutcome(ProbeStatus::Matches, 'The web tier holds the expected key ring.'),
        private readonly ?CallLog $log = null,
    ) {
        $this->queue = $outcomes;
    }

    public function observe(KeyRing $expected): ProbeOutcome
    {
        $this->observed[] = $expected->fingerprint();
        $this->log?->record('probe.observe ' . $expected->fingerprint());

        return array_shift($this->queue) ?? $this->fallback;
    }

    /**
     * Queues more answers after the ones already queued.
     */
    public function enqueue(ProbeOutcome ...$outcomes): void
    {
        foreach ($outcomes as $outcome) {
            $this->queue[] = $outcome;
        }
    }

    /**
     * Changes the answer given once the queue is empty.
     */
    public function answerFromNowOn(ProbeOutcome $fallback): void
    {
        $this->fallback = $fallback;
    }

    /**
     * @return list<string> the fingerprints of the rings asked about, oldest first
     */
    public function observed(): array
    {
        return $this->observed;
    }
}
