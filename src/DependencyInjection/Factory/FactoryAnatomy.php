<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;
use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;
use Symfony\Component\DependencyInjection\ContainerBuilder;

/**
 * Reads the shape of a factory: the class it creates, its creation methods, and which constructor
 * parameters of the created class the methods leave to the container.
 */
final class FactoryAnatomy
{
    /**
     * @param \ReflectionClass<object> $interface
     *
     * @return \ReflectionClass<object>
     *
     * @throws InvalidFactoryDefinition when the named class does not exist
     */
    public function target(\ReflectionClass $interface, ContainerBuilder $container): \ReflectionClass
    {
        $attributes = $interface->getAttributes(CreatesInstancesOf::class);
        if (count($attributes) !== 1) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s must carry exactly one #[CreatesInstancesOf] attribute.',
                $interface->getName(),
            ));
        }
        $class = $attributes[0]->newInstance()->class;
        $target = $container->getReflectionClass($class, false);
        if ($target === null) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s creates %s, which does not exist.',
                $interface->getName(),
                $class,
            ));
        }

        return $target;
    }

    /**
     * Every method of a factory interface creates; its name is free.
     *
     * @param \ReflectionClass<object> $interface
     *
     * @return list<\ReflectionMethod>
     */
    public function creationMethods(\ReflectionClass $interface): array
    {
        return $interface->getMethods();
    }

    /**
     * @param \ReflectionClass<object> $target
     *
     * @return list<\ReflectionParameter>
     */
    public function constructorParameters(\ReflectionClass $target): array
    {
        $constructor = $target->getConstructor();

        return $constructor === null ? [] : $constructor->getParameters();
    }

    /**
     * Constructor parameters of the created class that at least one creation method does not take, in
     * constructor order. The generated factory receives these from the container.
     *
     * @param \ReflectionClass<object> $interface
     * @param \ReflectionClass<object> $target
     *
     * @return list<\ReflectionParameter>
     */
    public function mirroredParameters(\ReflectionClass $interface, \ReflectionClass $target): array
    {
        $methods = $this->creationMethods($interface);
        $mirrored = [];
        foreach ($this->constructorParameters($target) as $parameter) {
            foreach ($methods as $method) {
                if (!$this->takes($method, $parameter->getName())) {
                    $mirrored[] = $parameter;
                    break;
                }
            }
        }

        return $mirrored;
    }

    /**
     * @param \ReflectionClass<object> $interface
     *
     * @return list<string> names of the creation methods that do not take the parameter
     */
    public function methodsNotTaking(\ReflectionClass $interface, string $parameter): array
    {
        $names = [];
        foreach ($this->creationMethods($interface) as $method) {
            if (!$this->takes($method, $parameter)) {
                $names[] = $method->getName();
            }
        }

        return $names;
    }

    public function takes(\ReflectionMethod $method, string $parameter): bool
    {
        foreach ($method->getParameters() as $candidate) {
            if ($candidate->getName() === $parameter) {
                return true;
            }
        }

        return false;
    }
}
