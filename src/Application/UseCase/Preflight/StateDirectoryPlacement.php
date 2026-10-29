<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;

/**
 * Decides whether the state directory may hold a run's key material where it is.
 *
 * - It must lie outside the web server's document root, or the kept keys could be served.
 * - When the Magento root path runs through a symbolic link (a release-style deploy, where the root links
 *   to the current release), it must lie outside the release the link points to: a deploy replaces the
 *   release with a fresh copy and would take the only copy of the kept keys with it. The default state
 *   directory sits inside the root, so such a store must name one elsewhere.
 *
 * Paths are compared once resolved, so a link anywhere along either path cannot hide the overlap; a
 * state directory that does not exist yet is resolved through its nearest existing parent.
 */
final class StateDirectoryPlacement
{
    public function __construct(
        private readonly RefusalFactory $refusals,
    ) {}

    /**
     * @param MagentoRoot $root           the root the command works on
     * @param string      $stateDirectory the absolute path of the state directory
     * @param string      $docroot        the document root, relative to the root
     *
     * @return Refusal|null why the state directory is refused, or null when it may be used
     */
    public function refusal(MagentoRoot $root, string $stateDirectory, string $docroot): ?Refusal
    {
        $state = $this->resolve($stateDirectory);
        $documentRoot = $this->resolve($root->file($docroot));
        if ($this->isInside($state, $documentRoot)) {
            return $this->refusals->create(RefusalReason::StateDirectoryInDocroot, sprintf(
                'The state directory %s lies inside the document root %s, where the web server could serve the kept keys; give --state-dir outside it.',
                $stateDirectory,
                $documentRoot,
            ));
        }

        $given = $this->normalise($root->path());
        $release = $this->resolve($root->path());
        if ($release !== $given && ($this->isInside($state, $release) || $this->isInside($this->normalise($stateDirectory), $given))) {
            return $this->refusals->create(RefusalReason::StateDirectoryInRelease, sprintf(
                'The Magento root %s runs through a symbolic link to %s, which a deploy replaces; give --state-dir outside that release, so the kept keys outlive it.',
                $given,
                $release,
            ));
        }

        return null;
    }

    private function isInside(string $path, string $directory): bool
    {
        return $path === $directory || str_starts_with($path, rtrim($directory, '/') . '/');
    }

    /**
     * The path with every symbolic link of its existing part resolved; the part that does not exist yet
     * is appended as it is.
     */
    private function resolve(string $path): string
    {
        $existing = $this->normalise($path);
        $missing = [];
        while (true) {
            $real = realpath($existing);
            if ($real !== false) {
                return $this->normalise($real . ($missing === [] ? '' : '/' . implode('/', array_reverse($missing))));
            }
            if ($existing === '/') {
                return $this->normalise($path);
            }
            $missing[] = basename($existing);
            $existing = dirname($existing);
        }
    }

    /**
     * The absolute path without empty, `.` and `..` segments and without a trailing slash.
     */
    private function normalise(string $path): string
    {
        $segments = [];
        foreach (explode('/', $path) as $segment) {
            if ($segment === '' || $segment === '.') {
                continue;
            }
            if ($segment === '..') {
                array_pop($segments);

                continue;
            }
            $segments[] = $segment;
        }

        return '/' . implode('/', $segments);
    }
}
