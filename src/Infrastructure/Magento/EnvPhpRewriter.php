<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigUnreadable;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKey;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\InvalidKeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\AtomicFileWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem\FilesystemFailure;

/**
 * Rewrites the deployment configuration with a new key ring and new `system` ciphertexts, as one
 * compare-and-swap of the whole file.
 *
 * 1. The file is found through any symbolic link: a link to a file shared between releases stays a
 *    link, and the shared file is the one replaced. Replacing the link would leave the shared file
 *    holding the old ring for the next release.
 * 2. The file is evaluated as it is now. Its ring must have the expected fingerprint and every changed
 *    path must still hold the change's expected old ciphertext; otherwise nothing is written, so
 *    another writer's change is never overwritten.
 * 3. The new array is rendered as the store renders it and written atomically beside the real file,
 *    with the file's mode, owner and group.
 * 4. The file is evaluated again and must give exactly the array that was meant. When it does not, the
 *    bytes on disk decide what happened:
 *    - they are exactly the bytes written: this write evaluates wrong, and the bytes the file held
 *      before are put back;
 *    - they are anything else: another writer replaced the file after this write landed, and its
 *      content is left as it is, never overwritten with an older copy. The write counts as stale, so a
 *      step that announced it resumes from its recorded pending state by reading the ring the file
 *      holds then.
 *
 * Comments in the file are lost, as they are when the store itself writes the file.
 */
final class EnvPhpRewriter
{
    public function __construct(
        private readonly DeploymentConfigFiles $files,
        private readonly DeploymentConfigMapper $mapper,
        private readonly NestedArray $tree,
        private readonly DeploymentConfigRenderer $renderer,
        private readonly AtomicFileWriter $writer,
    ) {}

    /**
     * @param list<SystemValueChange> $changes
     *
     * @throws StaleDeploymentConfig      when the file's ring or a changed path is not as expected (nothing is written),
     *                                    or another writer replaced the file before it could be read back (its content is kept)
     * @throws DeploymentConfigUnreadable when the file cannot be read or written, or this write does not read
     *                                    back as meant (the content from before is put back)
     */
    public function write(KeyRing $ring, string $expectedRingFingerprint, array $changes): void
    {
        $file = $this->files->deploymentConfigFile();
        $before = $this->files->bytes($file);
        $attributes = $this->files->attributes($file);
        $current = $this->files->load($file);

        $this->refuseAnotherRing($current, $expectedRingFingerprint, $file);
        $intended = $this->tree->with($this->applied($current, $changes, $file), DeploymentConfigMapper::CRYPT_KEY, $ring->export());

        $written = $this->renderer->render($intended);
        $this->replace($file, $written, $attributes);
        $this->verify($file, $intended, $written, $before, $attributes);
    }

    /**
     * @param array<mixed> $current
     */
    private function refuseAnotherRing(array $current, string $expected, string $file): void
    {
        try {
            $found = $this->mapper->keyRing($current, $file)->fingerprint();
        } catch (InvalidKeyRing|InvalidKey) {
            throw new StaleDeploymentConfig(sprintf(
                '%s holds a key ring that does not parse, not the expected ring %s; nothing was written.',
                $file,
                $expected,
            ));
        }
        if (!hash_equals($expected, $found)) {
            throw new StaleDeploymentConfig(sprintf(
                '%s holds the key ring %s, not the expected ring %s: another writer changed it. Nothing was written.',
                $file,
                $found,
                $expected,
            ));
        }
    }

    /**
     * @param array<mixed>            $config
     * @param list<SystemValueChange> $changes
     *
     * @return array<mixed>
     */
    private function applied(array $config, array $changes, string $file): array
    {
        foreach ($changes as $change) {
            $path = [DeploymentConfigMapper::SYSTEM, ...$change->path()];
            $held = $this->tree->get($config, $path);
            if (!is_string($held) || !hash_equals($change->expectedOld()->toString(), $held)) {
                throw new StaleDeploymentConfig(sprintf(
                    '%s no longer holds the expected value at system/%s: another writer changed it. Nothing was written.',
                    $file,
                    $change->pathString(),
                ));
            }
            $config = $this->tree->with($config, $path, $change->new()->toString());
        }

        return $config;
    }

    /**
     * @param array<mixed>                             $intended
     * @param array{mode: int, owner: int, group: int} $attributes
     *
     * @throws StaleDeploymentConfig      when another writer replaced the file after this write
     * @throws DeploymentConfigUnreadable when this write does not read back as meant
     */
    private function verify(string $file, array $intended, string $written, string $before, array $attributes): void
    {
        try {
            $matches = $this->files->load($file) === $intended;
        } catch (DeploymentConfigUnreadable) {
            $matches = false;
        }
        if ($matches) {
            return;
        }

        try {
            $onDisk = $this->files->bytes($file);
        } catch (DeploymentConfigUnreadable) {
            $onDisk = null;
        }
        if ($onDisk === null || !hash_equals($written, $onDisk)) {
            throw new StaleDeploymentConfig(sprintf(
                '%s changed after it was written: another writer replaced it before it could be read back. Its content was left as that writer wrote it; run the command again.',
                $file,
            ));
        }

        $this->replace($file, $before, $attributes);

        throw new DeploymentConfigUnreadable(sprintf(
            '%s did not read back as it was written; the content it held before was put back.',
            $file,
        ));
    }

    /**
     * @param array{mode: int, owner: int, group: int} $attributes
     */
    private function replace(string $file, string $bytes, array $attributes): void
    {
        try {
            $this->writer->write($file, $bytes, $attributes['mode'], $attributes['owner'], $attributes['group']);
        } catch (FilesystemFailure $failure) {
            throw new DeploymentConfigUnreadable($failure->getMessage(), 0, $failure);
        }
    }
}
