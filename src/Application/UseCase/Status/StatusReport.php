<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Status;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;

/**
 * Where the store's rotation stands: the active run, or the run that finished last when none is
 * active, with its state, history, waived checks and the summary of its last scan, and the commands the
 * operator may run next. With no run at all, only the next commands are known.
 *
 * The report reads the run; it never hands it out, so nothing can change the run through it.
 * Created through {@see StatusReportFactory}.
 */
final class StatusReport
{
    /**
     * @param RotationRun|null $run                       the run reported on, or null when the store holds none
     * @param list<RunCommand> $nextCommands              the commands allowed next
     * @param string|null      $deploymentRingFingerprint the fingerprint of the ring `env.php` holds now, null when it holds no usable one
     */
    public function __construct(
        private readonly ?RotationRun $run,
        private readonly array $nextCommands,
        private readonly ?string $deploymentRingFingerprint,
    ) {}

    public function hasRun(): bool
    {
        return $this->run !== null;
    }

    /**
     * Whether the run reported on is unfinished.
     */
    public function isActive(): bool
    {
        return $this->run?->isActive() ?? false;
    }

    public function runId(): ?string
    {
        return $this->run?->id()->toString();
    }

    public function state(): ?RunState
    {
        return $this->run?->state();
    }

    /**
     * The state a rollback started from, when one started.
     */
    public function rolledBackFrom(): ?RunState
    {
        return $this->run?->rolledBackFrom();
    }

    public function startedAt(): ?\DateTimeImmutable
    {
        return $this->run?->startedAt();
    }

    /**
     * @return list<array{state: RunState, at: \DateTimeImmutable}> every recorded state, oldest first
     */
    public function history(): array
    {
        return $this->run?->history() ?? [];
    }

    /**
     * @return list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}> the waived checks, in order
     */
    public function overrides(): array
    {
        return $this->run?->overrides() ?? [];
    }

    public function lastSummary(): ?ScanSummary
    {
        return $this->run?->lastSummary();
    }

    public function ringFingerprintBefore(): ?string
    {
        return $this->run?->ringFingerprintBefore();
    }

    public function ringFingerprint(): ?string
    {
        return $this->run?->ringFingerprint();
    }

    public function intendedRingFingerprint(): ?string
    {
        return $this->run?->intendedRingFingerprint();
    }

    /**
     * The fingerprint of the ring `env.php` holds now, null when it holds no usable one.
     */
    public function deploymentRingFingerprint(): ?string
    {
        return $this->deploymentRingFingerprint;
    }

    /**
     * Whether `env.php` holds neither the ring the unfinished run recorded nor the one it announced: a
     * deploy or another writer replaced it, and every writing command of the run will refuse until the
     * file the run wrote is back. A finished run, or a file without a usable ring, never counts.
     */
    public function deploymentRingDiffers(): bool
    {
        if ($this->run === null || !$this->run->isActive() || $this->deploymentRingFingerprint === null) {
            return false;
        }

        return $this->deploymentRingFingerprint !== $this->run->ringFingerprint()
            && $this->deploymentRingFingerprint !== $this->run->intendedRingFingerprint();
    }

    /**
     * @return list<int> the indices whose values the run moves: the one active before the run and the usable ones below it
     */
    public function sourceIndices(): array
    {
        if ($this->run === null) {
            return [];
        }
        return $this->run->movedIndices();
    }

    public function newIndex(): ?int
    {
        return $this->run?->newIndex();
    }

    public function lastRingWriteAt(): ?\DateTimeImmutable
    {
        return $this->run?->lastRingWriteAt();
    }

    public function probeSkipped(): bool
    {
        return $this->run?->probeSkipped() ?? false;
    }

    public function configCacheCleaned(): bool
    {
        return $this->run?->configCacheCleaned() ?? false;
    }

    /**
     * @return list<RunCommand>
     */
    public function nextCommands(): array
    {
        return $this->nextCommands;
    }
}
