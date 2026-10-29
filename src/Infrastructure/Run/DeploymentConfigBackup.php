<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;

/**
 * Keeps the bytes of the deployment configuration (through any symbolic link, the file it points to) in
 * the run directory as `env.php.bak`, readable by its owner only.
 *
 * The first copy of a run is the one kept: the file holds the keys as they were before the run changed
 * anything, and a run resumed after its first ring write must not replace it with a later state.
 */
final class DeploymentConfigBackup
{
    public function __construct(
        private readonly MagentoRootProvider $roots,
        private readonly RunDirectoryLayout $layout,
        private readonly AtomicFileWriter $writer,
        private readonly FileOperations $files,
    ) {}

    public function keep(RunId $id): void
    {
        $backup = $this->layout->runFile($id, RunDirectoryLayout::BACKUP_FILE);
        clearstatcache(true, $backup);
        if (is_file($backup)) {
            return;
        }

        $source = $this->roots->root()->deploymentConfigFile();
        $bytes = $this->files->attempt(sprintf('read "%s"', $source), static fn(): string|false => file_get_contents($source));
        $this->layout->ensureRunDirectory($id);
        $this->writer->write($backup, $bytes, RunDirectoryLayout::FILE_MODE);
    }
}
