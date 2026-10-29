<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RunningProcess;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\WorkerActivity;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;

/**
 * The checks every writing step repeats before it writes, each re-reading the store as it is now:
 *
 * - the deployment configuration holds the key ring the run expects (another writer may have changed it:
 *   the admin's encryption key page, a cache toggle served by a worker holding a stale copy of the file,
 *   a deploy), and that ring holds usable keys;
 * - the file holds only literal data, so rewriting it bakes no value of the environment into it;
 * - the tool can replace the file: the real file and the directory holding it are writable, so a ring
 *   write cannot fail halfway through a step that announced it;
 * - the tool runs as the owner of the file, unless the operator allows another user;
 * - the state directory lies where the kept keys are neither served nor replaced by a deploy;
 * - no process that started before the given key ring write still runs (an unknown start counts as
 *   earlier), unless the operator lets workers run.
 *
 * Every failing check is a refusal of its own; every check runs, so the operator sees all of them at
 * once. An override that let a failing check pass is listed, for the run to record.
 */
final class RunPreflight
{
    public function __construct(
        private readonly DeploymentConfigReader $config,
        private readonly RuntimeUser $user,
        private readonly MagentoRootProvider $roots,
        private readonly StateDirectoryProvider $stateDirectory,
        private readonly StateDirectoryPlacement $placement,
        private readonly WorkerActivity $workers,
        private readonly RefusalFactory $refusals,
        private readonly PreflightResultFactory $results,
    ) {}

    /**
     * @param string|null             $expectedRingFingerprint the ring the run expects, or null when any usable ring will do
     * @param \DateTimeImmutable|null $ringWrittenAt           the key ring write a process must have started after, or null to leave workers unchecked
     * @param bool                    $ignoreWorkers           whether processes older than that write may run
     * @param bool                    $allowOtherUser          whether the tool may run as another user than the owner of the file
     * @param ProbeSettings           $probeSettings           the command's probe settings, which name the document root
     */
    public function check(
        ?string $expectedRingFingerprint,
        ?\DateTimeImmutable $ringWrittenAt,
        bool $ignoreWorkers,
        bool $allowOtherUser,
        ProbeSettings $probeSettings,
    ): PreflightResult {
        $refusals = [];
        $waived = [];

        $ring = $this->ringRefusal($expectedRingFingerprint);
        if ($ring !== null) {
            $refusals[] = $ring;
        }
        if (!$this->config->holdsOnlyLiteralData()) {
            $refusals[] = $this->refusals->create(
                RefusalReason::DeploymentConfigNotLiteral,
                'The deployment configuration holds more than literal data (a function call, a variable, a constant or an include); rewriting it would replace them with the values they have now. Make it literal first.',
            );
        }

        if (!$this->config->isWritable()) {
            $refusals[] = $this->refusals->create(
                RefusalReason::DeploymentConfigNotWritable,
                'The deployment configuration cannot be replaced by this process: the file (the one a symbolic link points to) or the directory holding it is not writable. Fix the permissions, or run the tool as the owner of the file. Nothing was written.',
            );
        }

        $uid = $this->user->effectiveUid();
        $owner = $this->config->ownerUid();
        if ($uid !== $owner) {
            if ($allowOtherUser) {
                $waived[] = RunOverride::AllowOtherUser;
            } else {
                $refusals[] = $this->refusals->create(RefusalReason::OtherUser, sprintf(
                    'The tool runs as user %d, but the deployment configuration belongs to user %d; files it creates would not be writable by the store. Run it as user %d, or pass --allow-other-user.',
                    $uid,
                    $owner,
                    $owner,
                ));
            }
        }

        $placement = $this->placement->refusal($this->roots->root(), $this->stateDirectory->directory(), $probeSettings->docroot());
        if ($placement !== null) {
            $refusals[] = $placement;
        }

        $workers = $ringWrittenAt === null ? [] : $this->olderWorkers($ringWrittenAt);
        if ($workers !== []) {
            if ($ignoreWorkers) {
                $waived[] = RunOverride::IgnoreWorkers;
            } else {
                $refusals[] = $this->refusals->create(RefusalReason::WorkersRunning, sprintf(
                    'These processes may still hold an earlier key ring: %s. Stop them (cron, queue consumers, long commands), or pass --ignore-workers.',
                    implode('; ', array_map(static fn(RunningProcess $process): string => $process->description(), $workers)),
                ));
            }
        }

        return $this->results->create($refusals, $workers, $waived);
    }

    private function ringRefusal(?string $expectedRingFingerprint): ?Refusal
    {
        try {
            $found = $this->config->keyRing()->fingerprint();
        } catch (InvalidKeyRing|InvalidKey $unusable) {
            return $this->refusals->create(RefusalReason::RingUnusable, sprintf(
                'The key ring of the deployment configuration is not usable: %s',
                $unusable->getMessage(),
            ));
        }
        if ($expectedRingFingerprint === null || $found === $expectedRingFingerprint) {
            return null;
        }

        return $this->refusals->create(RefusalReason::RingChanged, sprintf(
            'The deployment configuration holds the key ring %s, but the run expects %s: another writer changed it (the encryption key page, a cache toggle, a deploy). Nothing was written.',
            $found,
            $expectedRingFingerprint,
        ));
    }

    /**
     * @return list<RunningProcess> the processes that may hold a key ring older than that write
     */
    private function olderWorkers(\DateTimeImmutable $ringWrittenAt): array
    {
        return array_values(array_filter(
            $this->workers->running(),
            static fn(RunningProcess $process): bool => $process->startedBefore($ringWrittenAt),
        ));
    }
}
