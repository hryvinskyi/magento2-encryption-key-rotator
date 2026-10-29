<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates rotation runs; implemented by the container build. Turning a stored snapshot into the
 * arguments of {@see restore()} is the application's snapshot reader's.
 */
#[CreatesInstancesOf(RotationRun::class)]
interface RotationRunFactory
{
    /**
     * A new run, in the state `started`.
     *
     * @param list<int> $oldUsableIndices the indices below the active one that hold a key
     *
     * @throws InvalidRun when the fields do not describe a run
     */
    public function start(
        RunId $id,
        string $ringFingerprintBefore,
        array $oldUsableIndices,
        int $activeIndexBefore,
        \DateTimeImmutable $startedAt,
    ): RotationRun;

    /**
     * A run as it was saved.
     *
     * @param list<int>           $oldUsableIndices
     * @param list<array{override: RunOverride, state: RunState, at: \DateTimeImmutable}> $overrides
     * @param list<array{state: RunState, at: \DateTimeImmutable}>  $history
     *
     * @throws InvalidRun when the fields do not describe a run
     */
    public function restore(
        RunId $id,
        string $ringFingerprintBefore,
        array $oldUsableIndices,
        int $activeIndexBefore,
        \DateTimeImmutable $startedAt,
        RunState $state,
        ?int $newIndex,
        string $ringFingerprint,
        ?string $intendedRingFingerprint,
        ?\DateTimeImmutable $lastRingWriteAt,
        bool $probeSkipped,
        ?ScanSummary $lastSummary,
        bool $configCacheCleaned,
        ?RunState $rolledBackFrom,
        array $overrides,
        array $history,
    ): RotationRun;
}
