<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Compiler;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\FactoryAnatomy;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Definition;
use Symfony\Component\DependencyInjection\Reference;

/**
 * Checks how autowiring wired every generated factory, before unused services are removed.
 *
 * Autowiring records a failure on the definition instead of throwing, and an unused failed service would
 * be removed silently; running before removal sees every factory, used or not. A factory resolves its
 * dependencies once and hands them to every object it creates, so the build fails when a constructor
 * parameter the methods leave to the container:
 * - could not be autowired;
 * - would receive `null` without having declared that as its default;
 * - points at a service that does not exist;
 * - points at a non-shared service (each created object would share one instance meant to be fresh).
 */
final class GeneratedFactoryWiringCheckPass implements CompilerPassInterface
{
    public function __construct(
        private readonly FactoryAnatomy $anatomy,
    ) {}

    public function process(ContainerBuilder $container): void
    {
        foreach (array_keys($container->findTaggedServiceIds(GeneratedFactoryPass::TAG)) as $id) {
            $definition = $container->getDefinition($id);
            $interface = $container->getReflectionClass($id, false);
            $generated = $container->getReflectionClass($definition->getClass(), false);
            if ($interface === null || $generated === null) {
                throw new InvalidFactoryDefinition(sprintf('Generated factory for %s cannot be reflected.', $id));
            }

            $this->refuseAutowiringErrors($interface, $definition);
            $constructor = $generated->getConstructor();
            if ($constructor === null) {
                continue;
            }
            $arguments = $definition->getArguments();
            foreach ($constructor->getParameters() as $parameter) {
                $this->checkArgument($container, $interface, $parameter, $arguments);
            }
        }
    }

    /**
     * @param \ReflectionClass<object> $interface
     */
    private function refuseAutowiringErrors(\ReflectionClass $interface, Definition $definition): void
    {
        $errors = $definition->getErrors();
        if ($errors === []) {
            return;
        }
        $first = reset($errors);
        $error = is_string($first) ? $first : 'autowiring failed.';
        $parameter = preg_match('/argument "\$(\w+)"/', $error, $match) === 1 ? $match[1] : null;

        throw new InvalidFactoryDefinition(sprintf(
            'Factory %s: %s %s',
            $interface->getName(),
            $parameter === null
                ? 'a constructor parameter left to the container cannot be autowired.'
                : $this->describe($interface, $parameter) . ' cannot be autowired.',
            $error,
        ));
    }

    /**
     * @param \ReflectionClass<object>  $interface
     * @param array<int|string, mixed> $arguments
     */
    private function checkArgument(
        ContainerBuilder $container,
        \ReflectionClass $interface,
        \ReflectionParameter $parameter,
        array $arguments,
    ): void {
        $name = $parameter->getName();
        $key = array_key_exists($parameter->getPosition(), $arguments) ? $parameter->getPosition() : '$' . $name;
        $hasDefault = $parameter->isDefaultValueAvailable();

        if (!array_key_exists($key, $arguments)) {
            if (!$hasDefault) {
                throw new InvalidFactoryDefinition(sprintf('Factory %s: %s is not wired.', $interface->getName(), $this->describe($interface, $name)));
            }

            return;
        }

        $argument = $arguments[$key];
        if ($argument === null && !$hasDefault) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s: %s would receive null; no service matches its type.',
                $interface->getName(),
                $this->describe($interface, $name),
            ));
        }
        if (!$argument instanceof Reference) {
            return;
        }

        $serviceId = (string) $argument;
        if (!$container->has($serviceId)) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s: %s references the missing service "%s".',
                $interface->getName(),
                $this->describe($interface, $name),
                $serviceId,
            ));
        }
        if (!$container->findDefinition($serviceId)->isShared()) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s: %s references the non-shared service "%s"; a factory would hand one instance to every object it creates.',
                $interface->getName(),
                $this->describe($interface, $name),
                $serviceId,
            ));
        }
    }

    /**
     * @param \ReflectionClass<object> $interface
     */
    private function describe(\ReflectionClass $interface, string $parameter): string
    {
        return sprintf(
            'constructor parameter $%s (not taken by %s)',
            $parameter,
            implode(', ', array_map(
                static fn(string $method): string => $method . '()',
                $this->anatomy->methodsNotTaking($interface, $parameter),
            )),
        );
    }
}
