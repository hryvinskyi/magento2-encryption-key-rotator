<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;

/**
 * Refuses, before any code is generated, a factory interface whose methods cannot be implemented as a
 * plain `new Target(...)` with arguments passed by name.
 *
 * The rules:
 * - the created class is instantiable through a public constructor;
 * - every method is an instance method returning a type the created class satisfies;
 * - every method parameter exists on the constructor by name, with a type the constructor accepts, and
 *   is neither variadic nor passed by reference;
 * - every constructor parameter a method does not take can be supplied by the container: it has a
 *   default, a wiring attribute, or a class/interface type. A builtin-typed or untyped parameter with
 *   none of those would silently receive nothing, so it fails here.
 *
 * Whether a class-typed parameter really resolves to a shared service is only known once autowiring has
 * run; that check belongs to the wiring check pass.
 */
final class FactoryContractValidator
{
    private const WIRING_ATTRIBUTE_NAMESPACE = 'Symfony\\Component\\DependencyInjection\\Attribute\\';

    public function __construct(
        private readonly FactoryAnatomy $anatomy,
        private readonly TypeCompatibility $types,
    ) {}

    /**
     * @param \ReflectionClass<object> $interface
     * @param \ReflectionClass<object> $target
     *
     * @throws InvalidFactoryDefinition naming the interface, the method and the parameter at fault
     */
    public function validate(\ReflectionClass $interface, \ReflectionClass $target): void
    {
        $this->validateTarget($interface, $target);
        $methods = $this->anatomy->creationMethods($interface);
        if ($methods === []) {
            throw new InvalidFactoryDefinition(sprintf('Factory %s declares no creation method.', $interface->getName()));
        }

        $constructorParameters = [];
        foreach ($this->anatomy->constructorParameters($target) as $parameter) {
            $constructorParameters[$parameter->getName()] = $parameter;
        }

        foreach ($methods as $method) {
            $this->validateMethod($interface, $target, $method, $constructorParameters);
        }
    }

    /**
     * @param \ReflectionClass<object> $interface
     * @param \ReflectionClass<object> $target
     */
    private function validateTarget(\ReflectionClass $interface, \ReflectionClass $target): void
    {
        if (!$target->isInstantiable()) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory %s creates %s, which cannot be instantiated through a public constructor.',
                $interface->getName(),
                $target->getName(),
            ));
        }
        foreach ($this->anatomy->constructorParameters($target) as $parameter) {
            if ($parameter->isVariadic() || $parameter->isPassedByReference()) {
                throw new InvalidFactoryDefinition(sprintf(
                    'Factory %s creates %s, whose constructor parameter $%s is variadic or passed by reference.',
                    $interface->getName(),
                    $target->getName(),
                    $parameter->getName(),
                ));
            }
        }
    }

    /**
     * @param \ReflectionClass<object>            $interface
     * @param \ReflectionClass<object>            $target
     * @param array<string, \ReflectionParameter> $constructorParameters
     */
    private function validateMethod(
        \ReflectionClass $interface,
        \ReflectionClass $target,
        \ReflectionMethod $method,
        array $constructorParameters,
    ): void {
        $where = sprintf('%s::%s()', $interface->getName(), $method->getName());
        if ($method->isStatic()) {
            throw new InvalidFactoryDefinition(sprintf('Factory method %s must not be static.', $where));
        }
        if (!$this->types->acceptsInstanceOf($method->getReturnType(), $interface, $target->getName())) {
            throw new InvalidFactoryDefinition(sprintf(
                'Factory method %s must declare a return type that %s satisfies.',
                $where,
                $target->getName(),
            ));
        }

        foreach ($method->getParameters() as $parameter) {
            $name = $parameter->getName();
            if ($parameter->isVariadic() || $parameter->isPassedByReference()) {
                throw new InvalidFactoryDefinition(sprintf(
                    'Factory method %s: parameter $%s must be neither variadic nor passed by reference.',
                    $where,
                    $name,
                ));
            }
            $constructorParameter = $constructorParameters[$name] ?? null;
            if ($constructorParameter === null) {
                throw new InvalidFactoryDefinition(sprintf(
                    'Factory method %s: parameter $%s does not exist on the constructor of %s.',
                    $where,
                    $name,
                    $target->getName(),
                ));
            }
            if (!$this->types->accepts($constructorParameter->getType(), $target, $parameter->getType(), $interface)) {
                throw new InvalidFactoryDefinition(sprintf(
                    'Factory method %s: parameter $%s is declared "%s", which the constructor of %s does not accept as "%s".',
                    $where,
                    $name,
                    (string) ($parameter->getType() ?? 'mixed'),
                    $target->getName(),
                    (string) ($constructorParameter->getType() ?? 'mixed'),
                ));
            }
        }

        foreach ($constructorParameters as $name => $constructorParameter) {
            if ($this->anatomy->takes($method, $name) || $this->containerCanSupply($constructorParameter, $target)) {
                continue;
            }
            throw new InvalidFactoryDefinition(sprintf(
                'Factory method %s does not take constructor parameter $%s of %s, and the container cannot supply it: '
                . 'it is declared "%s" with no default and no wiring attribute. Take it as a method parameter.',
                $where,
                $name,
                $target->getName(),
                (string) ($constructorParameter->getType() ?? 'mixed'),
            ));
        }
    }

    /**
     * @param \ReflectionClass<object> $target
     */
    private function containerCanSupply(\ReflectionParameter $parameter, \ReflectionClass $target): bool
    {
        if ($parameter->isDefaultValueAvailable()) {
            return true;
        }
        foreach ($parameter->getAttributes() as $attribute) {
            if (str_starts_with($attribute->getName(), self::WIRING_ATTRIBUTE_NAMESPACE)) {
                return true;
            }
        }

        return $this->types->namesOnlyClasses($parameter->getType(), $target);
    }
}
