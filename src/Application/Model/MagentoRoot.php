<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * The root directory of the Magento installation a command works on: an absolute path that holds
 * `app/etc/env.php`. The path is kept as given (a trailing slash dropped), not resolved, so a root
 * reached through a symbolic link is still recognisable as one.
 *
 * Created through {@see MagentoRootFactory}.
 */
final class MagentoRoot
{
    public const DEPLOYMENT_CONFIG = 'app/etc/env.php';
    public const COMMITTED_CONFIG = 'app/etc/config.php';

    private readonly string $path;

    /**
     * @throws InvalidMagentoRoot when the path is not absolute or holds no `app/etc/env.php`
     */
    public function __construct(string $path)
    {
        if (!str_starts_with($path, '/')) {
            throw new InvalidMagentoRoot(sprintf('The Magento root must be an absolute path; "%s" is not.', $path));
        }
        $normalised = $path === '/' ? $path : rtrim($path, '/');
        if (!is_file($normalised . '/' . self::DEPLOYMENT_CONFIG)) {
            throw new InvalidMagentoRoot(sprintf('"%s" holds no %s; it is not a Magento root.', $normalised, self::DEPLOYMENT_CONFIG));
        }

        $this->path = $normalised;
    }

    public function path(): string
    {
        return $this->path;
    }

    /**
     * The absolute path of a file or directory below the root.
     *
     * @param string $relative a path relative to the root, without a leading slash
     */
    public function file(string $relative): string
    {
        return rtrim($this->path, '/') . '/' . ltrim($relative, '/');
    }

    public function deploymentConfigFile(): string
    {
        return $this->file(self::DEPLOYMENT_CONFIG);
    }

    public function committedConfigFile(): string
    {
        return $this->file(self::COMMITTED_CONFIG);
    }
}
