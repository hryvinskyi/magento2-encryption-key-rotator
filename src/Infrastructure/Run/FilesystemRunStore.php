<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\ConflictingRuns;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunNotFound;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeySlot;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The runs of one Magento root, kept on disk below the state directory (layout in
 * {@see RunDirectoryLayout}): one directory per run, mode 0700, every file in it 0600 and replaced
 * atomically, and an flock()ed lock file so one process at a time works on the root.
 *
 * Each store holds its own lock, as a process does: a second store over the same directory, in this
 * process or another, cannot take the lock while the first holds it.
 */
final class FilesystemRunStore implements RunStore
{
    private ?StateDirectoryLock $lock = null;

    public function __construct(
        private readonly StateDirectoryLockFactory $locks,
        private readonly RunRecords $records,
        private readonly KeptMaterialFiles $kept,
        private readonly DeploymentConfigBackup $backup,
        private readonly RunDirectoryLayout $layout,
        private readonly RunDirectoryShredder $shredder,
    ) {}

    public function lock(): void
    {
        $this->lock ??= $this->locks->create();
        $this->lock->acquire();
    }

    public function unlock(): void
    {
        $this->lock?->release();
    }

    public function active(): ?RotationRun
    {
        $active = array_values(array_filter($this->records->all(), static fn(RotationRun $run): bool => $run->isActive()));
        if (count($active) > 1) {
            throw new ConflictingRuns(sprintf(
                'The state directory %s holds more than one unfinished run: %s. A Magento root has at most one; check which one is real before going on.',
                $this->layout->stateDirectory(),
                implode(', ', array_map(static fn(RotationRun $run): string => $run->id()->toString(), $active)),
            ));
        }

        return $active[0] ?? null;
    }

    public function latest(): ?RotationRun
    {
        $latest = null;
        foreach ($this->records->all() as $run) {
            if ($latest === null || $run->startedAt() >= $latest->startedAt()) {
                $latest = $run;
            }
        }

        return $latest;
    }

    public function get(RunId $id): RotationRun
    {
        return $this->records->find($id)
            ?? throw new RunNotFound(sprintf('The state directory %s holds no run %s.', $this->layout->stateDirectory(), $id->toString()));
    }

    public function save(RotationRun $run): void
    {
        $this->records->save($run);
    }

    public function backupDeploymentConfig(RunId $id): void
    {
        $this->backup->keep($id);
    }

    public function keepKey(RunId $id, KeptKeyRole $role, KeySlot $slot): void
    {
        $this->kept->keepKey($id, $role, $slot);
    }

    public function keptKeys(RunId $id, KeptKeyRole $role): array
    {
        return $this->kept->keptKeys($id, $role);
    }

    public function keepPlaceholders(RunId $id, array $placeholders): void
    {
        $this->kept->keepPlaceholders($id, $placeholders);
    }

    public function keptPlaceholders(RunId $id): array
    {
        return $this->kept->keptPlaceholders($id);
    }

    public function discard(RunId $id): void
    {
        $this->shredder->destroy($this->layout->runDirectory($id), RunDirectoryLayout::RUN_FILE);
    }
}
