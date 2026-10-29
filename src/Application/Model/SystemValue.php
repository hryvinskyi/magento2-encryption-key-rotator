<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * An encrypted value of a configuration file's `system` section: where it sits (the keys leading to
 * it, below `system`), the ciphertext, and which file holds it.
 *
 * Created through {@see SystemValueFactory}.
 */
final class SystemValue
{
    /**
     * @param list<string>      $path       the keys below `system` leading to the value, outermost first
     * @param Ciphertext        $ciphertext the value
     * @param SystemValueSource $source     the file that holds it
     *
     * @throws InvalidValue when the path is empty or holds an empty key
     */
    public function __construct(
        private readonly array $path,
        private readonly Ciphertext $ciphertext,
        private readonly SystemValueSource $source,
    ) {
        if ($path === [] || in_array('', $path, true)) {
            throw new InvalidValue('A configuration path names at least one key, and no key is empty.');
        }
    }

    /**
     * @return list<string> the keys below `system` leading to the value, outermost first
     */
    public function path(): array
    {
        return $this->path;
    }

    /**
     * The path as the configuration names it: the keys joined by `/`.
     */
    public function pathString(): string
    {
        return implode('/', $this->path);
    }

    public function ciphertext(): Ciphertext
    {
        return $this->ciphertext;
    }

    public function source(): SystemValueSource
    {
        return $this->source;
    }
}
