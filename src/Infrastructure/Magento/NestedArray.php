<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento;

/**
 * Reads and replaces values deep inside a configuration array by the keys leading to them, the way the
 * store addresses its configuration: `['db', 'connection', 'default']` for `db/connection/default`.
 * A key that reads as an integer addresses the integer key, as it does in PHP.
 */
final class NestedArray
{
    /**
     * @param array<mixed> $tree
     * @param list<string> $path the keys, outermost first
     *
     * @return bool whether every key on the path exists, with an array at every step before the last
     */
    public function has(array $tree, array $path): bool
    {
        $node = $tree;
        foreach ($path as $key) {
            if (!is_array($node) || !array_key_exists($key, $node)) {
                return false;
            }
            $node = $node[$key];
        }

        return true;
    }

    /**
     * @param array<mixed> $tree
     * @param list<string> $path the keys, outermost first
     *
     * @return mixed the value at the path, or null when the path does not exist
     */
    public function get(array $tree, array $path): mixed
    {
        $node = $tree;
        foreach ($path as $key) {
            if (!is_array($node) || !array_key_exists($key, $node)) {
                return null;
            }
            $node = $node[$key];
        }

        return $node;
    }

    /**
     * The tree with the value at the path; every other value, and the order of every key, is kept. Keys
     * missing on the way are added as arrays at the end of their parent.
     *
     * @param array<mixed> $tree
     * @param list<string> $path  the keys, outermost first; at least one
     * @param mixed        $value the new value
     *
     * @return array<mixed>
     *
     * @throws \InvalidArgumentException when the path is empty or runs through a value that is not an array
     */
    public function with(array $tree, array $path, mixed $value): array
    {
        $key = array_shift($path);
        if ($key === null) {
            throw new \InvalidArgumentException('A configuration path names at least one key.');
        }
        if ($path === []) {
            $tree[$key] = $value;

            return $tree;
        }

        $child = $tree[$key] ?? [];
        if (!is_array($child)) {
            throw new \InvalidArgumentException(sprintf('The configuration key "%s" holds a value, not a section.', $key));
        }
        $tree[$key] = $this->with($child, $path, $value);

        return $tree;
    }
}
