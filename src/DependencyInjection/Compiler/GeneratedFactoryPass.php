<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Compiler;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryAnatomy;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryContractValidator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryInterfaceLocator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactorySourceGenerator;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\GeneratedFactoryWriter;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Implements every factory interface with generated code and registers it as the service for that
 * interface.
 *
 * Runs before optimisation, so autowiring then wires each generated constructor like any other service.
 * The generated file is loaded by the dumped container through the definition's file, never by the
 * autoloader. An interface that already has a service (a hand-written implementation, an alias) fails
 * the build: a factory is implemented only by generated code.
 */
final class GeneratedFactoryPass implements CompilerPassInterface
{
    public const TAG = 'key_rotator.generated_factory';

    public function __construct(
        private readonly FactoryInterfaceLocator $locator,
        private readonly FactoryAnatomy $anatomy,
        private readonly FactoryContractValidator $validator,
        private readonly FactorySourceGenerator $generator,
        private readonly GeneratedFactoryWriter $writer,
    ) {}

    public function process(ContainerBuilder $container): void
    {
        foreach ($this->locator->locate($container) as $interface) {
            $id = $interface->getName();
            if ($container->has($id)) {
                throw new InvalidFactoryDefinition(sprintf(
                    'Factory %s already has a service; a factory interface is implemented only by generated code.',
                    $id,
                ));
            }

            $target = $this->anatomy->target($interface, $container);
            $this->validator->validate($interface, $target);
            $generated = $this->generator->generate($interface, $target);
            $file = $this->writer->write($generated['shortName'], $generated['source']);
            require_once $file;

            $container->register($id, $generated['class'])
                ->setFile($file)
                ->setAutowired(true)
                ->setPublic(false)
                ->addTag(self::TAG);
        }
    }
}
