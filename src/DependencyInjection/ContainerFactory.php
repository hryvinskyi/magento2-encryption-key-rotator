<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Compiler\GeneratedFactoryPass;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Compiler\GeneratedFactoryWiringCheckPass;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryAnatomy;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryContractValidator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryInterfaceLocator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactorySourceGenerator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\GeneratedFactoryWriter;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\PhpCodeRenderer;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\TypeCompatibility;
use Symfony\Component\Config\FileLocator;
use Symfony\Component\DependencyInjection\Compiler\PassConfig;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Dumper\PhpDumper;
use Symfony\Component\DependencyInjection\Loader\PhpFileLoader;

/**
 * The composition root of the build: compiles the service container and dumps it as PHP.
 *
 * It runs when the phar is built, in tests, and on the fly in a source checkout; the phar itself only
 * loads the dumped result. The build directory receives `Container.php`, the generated factory classes
 * beside it, and `bootstrap.php`, which loads the container class and returns an instance of it. The
 * container is dumped with its own path known, so every generated file is referenced relative to the
 * container file: the directory can be moved, or packed into a phar, and still loads.
 */
final class ContainerFactory
{
    public const CONTAINER_NAMESPACE = 'Hryvinskyi\\EncryptionKeyRotator\\Generated';
    public const CONTAINER_CLASS_NAME = 'KeyRotatorContainer';
    public const CONTAINER_FILE = 'Container.php';
    public const BOOTSTRAP_FILE = 'bootstrap.php';

    /**
     * @param string                $serviceConfigFile PHP service configuration to load
     * @param array<string, string> $factorySources    namespace prefix => directory searched for factory interfaces
     */
    public function __construct(
        private readonly string $serviceConfigFile,
        private readonly array $factorySources,
    ) {}

    /**
     * Compiles the container; generated factory classes are written into the build directory.
     */
    public function compile(string $buildDirectory): ContainerBuilder
    {
        $anatomy = new FactoryAnatomy();
        $types = new TypeCompatibility();

        $builder = new ContainerBuilder();
        $builder->addCompilerPass(
            new GeneratedFactoryPass(
                new FactoryInterfaceLocator($this->factorySources),
                $anatomy,
                new FactoryContractValidator($anatomy, $types),
                new FactorySourceGenerator($anatomy, new PhpCodeRenderer()),
                new GeneratedFactoryWriter($buildDirectory),
            ),
            PassConfig::TYPE_BEFORE_OPTIMIZATION,
        );
        $builder->addCompilerPass(
            new GeneratedFactoryWiringCheckPass($anatomy),
            PassConfig::TYPE_BEFORE_REMOVING,
        );

        $loader = new PhpFileLoader($builder, new FileLocator(dirname($this->serviceConfigFile)));
        $loader->load(basename($this->serviceConfigFile));
        $builder->compile();

        return $builder;
    }

    /**
     * Compiles the container and dumps it into the build directory.
     *
     * @return string the path of `bootstrap.php`, which returns the container when required
     */
    public function dump(string $buildDirectory): string
    {
        if (!is_dir($buildDirectory) && !mkdir($buildDirectory, 0755, true) && !is_dir($buildDirectory)) {
            throw new \RuntimeException(sprintf('Cannot create the build directory "%s".', $buildDirectory));
        }
        $builder = $this->compile($buildDirectory);
        $directory = realpath($buildDirectory);
        if ($directory === false) {
            throw new \RuntimeException(sprintf('Cannot resolve the build directory "%s".', $buildDirectory));
        }
        $file = $directory . '/' . self::CONTAINER_FILE;

        $code = (new PhpDumper($builder))->dump([
            'class' => self::CONTAINER_CLASS_NAME,
            'namespace' => self::CONTAINER_NAMESPACE,
            'file' => $file,
            'debug' => false,
        ]);
        if (!is_string($code)) {
            throw new \RuntimeException('The container dumper returned several files; one was expected.');
        }

        $this->write($file, $code);
        $this->write($directory . '/' . self::BOOTSTRAP_FILE, sprintf(
            "<?php\n\ndeclare(strict_types=1);\n\nrequire_once __DIR__ . '/%s';\n\nreturn new \\%s\\%s();\n",
            self::CONTAINER_FILE,
            self::CONTAINER_NAMESPACE,
            self::CONTAINER_CLASS_NAME,
        ));

        return $directory . '/' . self::BOOTSTRAP_FILE;
    }

    private function write(string $file, string $content): void
    {
        $temporary = $file . '.' . bin2hex(random_bytes(6)) . '.tmp';
        if (file_put_contents($temporary, $content) !== strlen($content) || !chmod($temporary, 0644) || !rename($temporary, $file)) {
            if (is_file($temporary)) {
                unlink($temporary);
            }
            throw new \RuntimeException(sprintf('Cannot write "%s".', $file));
        }
    }
}
