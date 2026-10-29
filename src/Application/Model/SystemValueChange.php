<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;

/**
 * A rewrite of one encrypted `system` value of the deployment configuration: at that path, replace
 * exactly the expected old ciphertext with the new one. A path that no longer holds the expected value
 * fails the whole write, so a value someone changed meanwhile is never overwritten.
 *
 * Created through {@see SystemValueChangeFactory}.
 */
final class SystemValueChange
{
    /**
     * @param list<string> $path        the keys below `system` leading to the value, outermost first
     * @param Ciphertext   $expectedOld the value the path must still hold
     * @param Ciphertext   $new         the value to write
     *
     * @throws InvalidValue when the path is empty or holds an empty key
     */
    public function __construct(
        private readonly array $path,
        private readonly Ciphertext $expectedOld,
        private readonly Ciphertext $new,
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

    public function expectedOld(): Ciphertext
    {
        return $this->expectedOld;
    }

    public function new(): Ciphertext
    {
        return $this->new;
    }
}
