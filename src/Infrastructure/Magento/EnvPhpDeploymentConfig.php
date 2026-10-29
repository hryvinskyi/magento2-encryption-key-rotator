<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;

/**
 * The store's configuration files on disk: `app/etc/env.php`, read and written, and
 * `app/etc/config.php`, only read.
 *
 * Every read evaluates the file anew in a separate PHP process (see {@see PhpArrayFileLoader}), so a
 * change made by another writer is always seen and nothing of the store's code runs inside this
 * process. Writes go through {@see EnvPhpRewriter}: a compare-and-swap on the ring fingerprint and on
 * each changed value, an atomic replacement of the real file behind any symbolic link, and a read-back.
 */
final class EnvPhpDeploymentConfig implements DeploymentConfigReader, DeploymentConfigWriter
{
    public function __construct(
        private readonly DeploymentConfigFiles $files,
        private readonly DeploymentConfigMapper $mapper,
        private readonly LiteralDataInspector $literal,
        private readonly EnvPhpRewriter $rewriter,
        private readonly SecretLeaves $secrets,
    ) {}

    public function keyRing(): KeyRing
    {
        $file = $this->files->deploymentConfigFile();

        return $this->mapper->keyRing($this->files->load($file), $file);
    }

    public function databaseSettings(): DatabaseSettings
    {
        $file = $this->files->deploymentConfigFile();

        return $this->mapper->databaseSettings($this->files->load($file), $file);
    }

    public function systemValues(): array
    {
        $file = $this->files->deploymentConfigFile();

        return $this->mapper->systemValues($this->files->load($file), SystemValueSource::Env, $file);
    }

    public function committedSystemValues(): array
    {
        $file = $this->files->committedConfigFile();
        if ($file === null) {
            return [];
        }

        return $this->mapper->systemValues($this->files->load($file), SystemValueSource::Committed, $file);
    }

    public function ownerUid(): int
    {
        return $this->files->attributes($this->files->deploymentConfigFile())['owner'];
    }

    public function holdsOnlyLiteralData(): bool
    {
        return $this->literal->holdsOnlyLiteralData($this->files->bytes($this->files->deploymentConfigFile()));
    }

    public function isWritable(): bool
    {
        $file = $this->files->deploymentConfigFile();
        $directory = realpath(dirname($file));

        return is_writable($file) && $directory !== false && is_writable($directory);
    }

    public function secretStrings(): array
    {
        return $this->secrets->collect($this->files->load($this->files->deploymentConfigFile()));
    }

    public function write(KeyRing $ring, string $expectedRingFingerprint, array $changes): void
    {
        $this->rewriter->write($ring, $expectedRingFingerprint, $changes);
    }
}
