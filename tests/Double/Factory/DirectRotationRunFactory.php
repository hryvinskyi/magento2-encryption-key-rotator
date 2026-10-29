<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectRotationRunFactory implements RotationRunFactory
{
    public function start(
        RunId $id,
        string $ringFingerprintBefore,
        array $oldUsableIndices,
        int $activeIndexBefore,
        \DateTimeImmutable $startedAt,
    ): RotationRun {
        return new RotationRun($id, $ringFingerprintBefore, $oldUsableIndices, $activeIndexBefore, $startedAt);
    }

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
    ): RotationRun {
        return new RotationRun(
            id: $id,
            ringFingerprintBefore: $ringFingerprintBefore,
            oldUsableIndices: $oldUsableIndices,
            activeIndexBefore: $activeIndexBefore,
            startedAt: $startedAt,
            state: $state,
            newIndex: $newIndex,
            ringFingerprint: $ringFingerprint,
            intendedRingFingerprint: $intendedRingFingerprint,
            lastRingWriteAt: $lastRingWriteAt,
            probeSkipped: $probeSkipped,
            lastSummary: $lastSummary,
            configCacheCleaned: $configCacheCleaned,
            rolledBackFrom: $rolledBackFrom,
            overrides: $overrides,
            history: $history,
        );
    }
}
