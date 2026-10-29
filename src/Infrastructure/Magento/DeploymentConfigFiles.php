<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FileOperations;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;

/**
 * Finds and reads the configuration files of the command's Magento root: the deployment configuration
 * (`app/etc/env.php`) through any symbolic link to the file it points to, and the committed
 * configuration (`app/etc/config.php`), which a store may not have. The root is asked for on every call,
 * never remembered.
 */
final class DeploymentConfigFiles
{
    public function __construct(
        private readonly MagentoRootProvider $roots,
        private readonly PhpArrayFileLoader $loader,
        private readonly FileOperations $files,
    ) {}

    /**
     * The real path of the deployment configuration: when `app/etc/env.php` is a symbolic link, the file
     * it points to, which is the file to read and to replace.
     *
     * @throws DeploymentConfigUnreadable when the file does not exist
     */
    public function deploymentConfigFile(): string
    {
        $path = $this->roots->root()->deploymentConfigFile();
        clearstatcache(true);
        $real = realpath($path);
        if ($real === false || !is_file($real)) {
            throw new DeploymentConfigUnreadable(sprintf('%s does not exist.', $path));
        }

        return $real;
    }

    /**
     * The real path of the committed configuration, or null when the store has none.
     */
    public function committedConfigFile(): ?string
    {
        $path = $this->roots->root()->committedConfigFile();
        clearstatcache(true);
        $real = realpath($path);

        return $real !== false && is_file($real) ? $real : null;
    }

    /**
     * @return array<mixed> the array the file returns
     *
     * @throws DeploymentConfigUnreadable when it cannot be evaluated or does not return an array
     */
    public function load(string $file): array
    {
        return $this->loader->load($file);
    }

    /**
     * @throws DeploymentConfigUnreadable when the file cannot be read
     */
    public function bytes(string $file): string
    {
        try {
            return $this->files->attempt(sprintf('read "%s"', $file), static fn(): string|false => file_get_contents($file));
        } catch (FilesystemFailure $failure) {
            throw new DeploymentConfigUnreadable($failure->getMessage(), 0, $failure);
        }
    }

    /**
     * @return array{mode: int, owner: int, group: int} the permission bits, the user id and the group id
     *
     * @throws DeploymentConfigUnreadable when the file cannot be inspected
     */
    public function attributes(string $file): array
    {
        clearstatcache(true, $file);
        try {
            $status = $this->files->attempt(sprintf('inspect "%s"', $file), static fn(): array|false => stat($file));
        } catch (FilesystemFailure $failure) {
            throw new DeploymentConfigUnreadable($failure->getMessage(), 0, $failure);
        }

        return ['mode' => $status['mode'] & 07777, 'owner' => $status['uid'], 'group' => $status['gid']];
    }
}
