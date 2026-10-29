<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Run\CorruptRunFile;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\RunSnapshotReader;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * The run records of a state directory: each run's `run.json`, the JSON of its snapshot, read back
 * through {@see RunSnapshotReader} so a loaded run is exactly the run that was saved.
 */
final class RunRecords
{
    public function __construct(
        private readonly RunDirectoryLayout $layout,
        private readonly PrivateJsonFile $json,
        private readonly RunSnapshotReader $snapshots,
    ) {}

    public function save(RotationRun $run): void
    {
        $this->layout->ensureRunDirectory($run->id());
        $this->json->write($this->layout->runFile($run->id(), RunDirectoryLayout::RUN_FILE), $run->snapshot());
    }

    /**
     * @return RotationRun|null the run, or null when the state directory holds no record of it
     *
     * @throws CorruptRunFile when the record cannot be read back
     */
    public function find(RunId $id): ?RotationRun
    {
        $file = $this->layout->runFile($id, RunDirectoryLayout::RUN_FILE);
        if (!$this->json->exists($file)) {
            return null;
        }

        return $this->snapshots->read($id->toString(), $this->json->read($file, sprintf('the record of run %s', $id->toString())));
    }

    /**
     * @return list<RotationRun> every recorded run, by ascending id
     *
     * @throws CorruptRunFile when a record cannot be read back
     */
    public function all(): array
    {
        $runs = [];
        foreach ($this->layout->runIds() as $id) {
            $file = $this->layout->stateDirectory() . '/' . $id . '/' . RunDirectoryLayout::RUN_FILE;
            $runs[] = $this->snapshots->read($id, $this->json->read($file, sprintf('the record of run %s', $id)));
        }

        return $runs;
    }
}
