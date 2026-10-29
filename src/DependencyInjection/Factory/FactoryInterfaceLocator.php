<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Finds the factory interfaces of the configured source roots.
 *
 * Each root is a PSR-4 pair (namespace prefix, directory). Every `.php` file below the directory is
 * mapped to its class name; the interfaces among them that carry {@see CreatesInstancesOf} are factories.
 * The scan covers interfaces whether or not the service configuration loads their directory, so a
 * factory placed beside the value objects it creates is still found.
 */
final class FactoryInterfaceLocator
{
    /**
     * @param array<string, string> $sources namespace prefix (ending in a backslash) => directory
     */
    public function __construct(
        private readonly array $sources,
    ) {}

    /**
     * @return list<\ReflectionClass<object>> the factory interfaces, ordered by name
     */
    public function locate(ContainerBuilder $container): array
    {
        $found = [];
        foreach ($this->sources as $namespace => $directory) {
            foreach ($this->classNamesUnder($namespace, $directory) as $class) {
                $reflection = $container->getReflectionClass($class, false);
                if ($reflection === null || !$reflection->isInterface()) {
                    continue;
                }
                if ($reflection->getAttributes(CreatesInstancesOf::class) === []) {
                    continue;
                }
                $found[$reflection->getName()] = $reflection;
            }
        }
        ksort($found);

        return array_values($found);
    }

    /**
     * @return list<string>
     */
    private function classNamesUnder(string $namespace, string $directory): array
    {
        $root = realpath($directory);
        if ($root === false || !is_dir($root)) {
            throw new InvalidFactoryDefinition(sprintf('Factory source directory "%s" does not exist.', $directory));
        }

        $classes = [];
        foreach ($this->phpFilesUnder($root) as $file) {
            $relative = substr($file, strlen($root) + 1, -4);
            $classes[] = $namespace . str_replace('/', '\\', $relative);
        }

        return $classes;
    }

    /**
     * @return list<string>
     */
    private function phpFilesUnder(string $directory): array
    {
        $entries = scandir($directory);
        if ($entries === false) {
            throw new InvalidFactoryDefinition(sprintf('Factory source directory "%s" cannot be read.', $directory));
        }

        $files = [];
        foreach ($entries as $entry) {
            if ($entry === '.' || $entry === '..') {
                continue;
            }
            $path = $directory . '/' . $entry;
            if (is_dir($path)) {
                array_push($files, ...$this->phpFilesUnder($path));
                continue;
            }
            if (preg_match('/^[A-Za-z_][A-Za-z0-9_]*\.php$/', $entry) === 1) {
                $files[] = $path;
            }
        }

        return $files;
    }
}
