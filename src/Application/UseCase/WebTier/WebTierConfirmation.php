<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\WebTier;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeOutcome;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Pause;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WebTierProbe;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Psr\Clock\ClockInterface;

/**
 * Confirms that the web tier holds a key ring. The web tier may keep an older copy of the deployment
 * configuration for a while after a write (an opcode cache that does not revalidate keeps it until the
 * pool reloads), so a confirmation after a write asks again every few seconds until the ring matches or
 * the command's wait budget is spent.
 *
 * No value may move toward a key before the web tier is confirmed to hold it: a web tier still on the
 * previous ring would read such values as empty.
 */
final class WebTierConfirmation
{
    /**
     * Seconds between two questions to the web tier.
     */
    public const POLL_INTERVAL = 5;

    public function __construct(
        private readonly WebTierProbe $probe,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
        private readonly Pause $pause,
    ) {}

    /**
     * Asks once: proves the transport reaches the web tier and that it holds the ring now.
     */
    public function once(KeyRing $expected): ProbeOutcome
    {
        $this->progress->step(sprintf('Asking the web tier whether it holds the key ring %s', $expected->fingerprint()));

        return $this->probe->observe($expected);
    }

    /**
     * Asks until the web tier holds the ring or the wait budget of the settings is spent, and returns the
     * last answer.
     */
    public function await(KeyRing $expected, ProbeSettings $settings): ProbeOutcome
    {
        $this->progress->step(sprintf(
            'Waiting up to %d seconds for the web tier to hold the key ring %s',
            $settings->waitSeconds(),
            $expected->fingerprint(),
        ));
        $deadline = $this->seconds($this->clock->now()) + $settings->waitSeconds();
        while (true) {
            $outcome = $this->probe->observe($expected);
            if ($outcome->matches()) {
                return $outcome;
            }
            $remaining = $deadline - $this->seconds($this->clock->now());
            if ($remaining <= 0) {
                return $outcome;
            }
            $this->pause->pause((int) ceil(min(self::POLL_INTERVAL, $remaining)));
        }
    }

    private function seconds(\DateTimeImmutable $moment): float
    {
        return (float) $moment->format('U.u');
    }
}
