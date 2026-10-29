<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;

/**
 * Reports where the store's rotation stands, read-only and without the run store's lock: the active run,
 * or the latest finished one, the commands allowed next, and the key ring `env.php` holds now. The last
 * one lets an operator see that a deploy put back a copy of `env.php` from before the run's ring write.
 */
final class ReportStatus
{
    public function __construct(
        private readonly RunStore $runs,
        private readonly DeploymentConfigReader $config,
        private readonly StatusReportFactory $reports,
    ) {}

    /**
     * @throws ConflictingRuns when the run store holds more than one unfinished run
     */
    public function status(): StatusReport
    {
        $run = $this->runs->active() ?? $this->runs->latest();

        return $this->reports->create($run, RunCommand::allowedAfter($run?->state()), $this->deploymentRingFingerprint());
    }

    /**
     * The fingerprint of the ring `env.php` holds now, or null when the file holds no usable ring: status
     * reports what it finds and never fails on it.
     */
    private function deploymentRingFingerprint(): ?string
    {
        try {
            return $this->config->keyRing()->fingerprint();
        } catch (DeploymentConfigUnreadable | InvalidKeyRing | InvalidKey) {
            return null;
        }
    }
}
