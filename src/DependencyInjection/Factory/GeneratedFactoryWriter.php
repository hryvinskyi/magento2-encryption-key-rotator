<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;

/**
 * Writes generated factory classes into the build directory, one `<class short name>.php` per class.
 *
 * A class is named after the hash of its own source, so an existing file already holds exactly that
 * source and is never rewritten (a production opcache that does not revalidate keeps serving it
 * correctly). New files are written to a temporary name and renamed into place.
 */
final class GeneratedFactoryWriter
{
    public function __construct(
        private readonly string $directory,
    ) {}

    /**
     * @return string the absolute path of the file holding the class
     */
    public function write(string $shortName, string $source): string
    {
        $directory = $this->directory();
        $path = $directory . '/' . $shortName . '.php';
        if (is_file($path)) {
            return $path;
        }

        $temporary = tempnam($directory, '.factory');
        if ($temporary === false) {
            throw new InvalidFactoryDefinition(sprintf('Cannot create a temporary file in "%s".', $directory));
        }
        if (file_put_contents($temporary, $source) !== strlen($source) || !chmod($temporary, 0644) || !rename($temporary, $path)) {
            if (is_file($temporary)) {
                unlink($temporary);
            }
            throw new InvalidFactoryDefinition(sprintf('Cannot write the generated factory "%s".', $path));
        }

        return $path;
    }

    private function directory(): string
    {
        if (!is_dir($this->directory) && !mkdir($this->directory, 0755, true) && !is_dir($this->directory)) {
            throw new InvalidFactoryDefinition(sprintf('Cannot create the build directory "%s".', $this->directory));
        }
        $real = realpath($this->directory);
        if ($real === false) {
            throw new InvalidFactoryDefinition(sprintf('Cannot resolve the build directory "%s".', $this->directory));
        }

        return $real;
    }
}
