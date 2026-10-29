<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;

/**
 * Renders the PHP fragments a generated factory copies from reflection: types, default values and the
 * parameter attributes that steer wiring or redaction.
 */
final class PhpCodeRenderer
{
    /**
     * Attributes copied onto a generated parameter: the container's wiring attributes, so the generated
     * constructor is wired exactly as the created class would be, and the marker that keeps an argument
     * out of stack traces.
     */
    private const COPIED_ATTRIBUTE_NAMESPACE = 'Symfony\\Component\\DependencyInjection\\Attribute\\';
    private const COPIED_ATTRIBUTES = [\SensitiveParameter::class];

    /**
     * @param \ReflectionClass<object> $context the class that declares the type (resolves `self`)
     */
    public function type(?\ReflectionType $type, \ReflectionClass $context): string
    {
        if ($type === null) {
            return '';
        }
        if ($type instanceof \ReflectionNamedType) {
            $name = $this->typeName($type->getName(), $context);
            $nullable = $type->allowsNull() && !in_array($name, ['null', 'mixed'], true);

            return ($nullable ? '?' : '') . $name;
        }
        if ($type instanceof \ReflectionUnionType) {
            $members = [];
            foreach ($type->getTypes() as $member) {
                $members[] = $member instanceof \ReflectionIntersectionType
                    ? '(' . $this->type($member, $context) . ')'
                    : $this->type($member, $context);
            }

            return implode('|', $members);
        }
        if ($type instanceof \ReflectionIntersectionType) {
            $members = [];
            foreach ($type->getTypes() as $member) {
                $members[] = $this->type($member, $context);
            }

            return implode('&', $members);
        }

        throw new InvalidFactoryDefinition(sprintf('Type "%s" cannot be rendered.', (string) $type));
    }

    /**
     * The `= default` suffix of a parameter, or an empty string when it has none.
     */
    public function defaultSuffix(\ReflectionParameter $parameter): string
    {
        if (!$parameter->isDefaultValueAvailable()) {
            return '';
        }
        if ($parameter->isDefaultValueConstant()) {
            return ' = ' . $this->constantName($parameter);
        }

        return ' = ' . $this->value($parameter->getDefaultValue(), $this->describe($parameter));
    }

    /**
     * The copied attributes of a parameter, each followed by a space.
     */
    public function attributes(\ReflectionParameter $parameter): string
    {
        $rendered = '';
        foreach ($parameter->getAttributes() as $attribute) {
            $name = $attribute->getName();
            if (!str_starts_with($name, self::COPIED_ATTRIBUTE_NAMESPACE) && !in_array($name, self::COPIED_ATTRIBUTES, true)) {
                continue;
            }
            $arguments = [];
            foreach ($attribute->getArguments() as $key => $value) {
                $argument = $this->value($value, $this->describe($parameter));
                $arguments[] = is_string($key) ? $key . ': ' . $argument : $argument;
            }
            $rendered .= '#[\\' . $name . ($arguments === [] ? '' : '(' . implode(', ', $arguments) . ')') . '] ';
        }

        return $rendered;
    }

    /**
     * A literal PHP expression for a constant value.
     *
     * @throws InvalidFactoryDefinition when the value holds an object or a resource
     */
    public function value(mixed $value, string $owner): string
    {
        if ($value === null || is_scalar($value)) {
            return var_export($value, true);
        }
        if (is_array($value)) {
            $items = [];
            foreach ($value as $key => $item) {
                $items[] = var_export($key, true) . ' => ' . $this->value($item, $owner);
            }

            return '[' . implode(', ', $items) . ']';
        }

        throw new InvalidFactoryDefinition(sprintf(
            '%s has a %s value that generated code cannot reproduce; use a constant expression.',
            $owner,
            get_debug_type($value),
        ));
    }

    /**
     * @param \ReflectionClass<object> $context
     */
    private function typeName(string $name, \ReflectionClass $context): string
    {
        $lower = strtolower($name);
        if ($lower === 'self') {
            return '\\' . $context->getName();
        }
        if ($lower === 'static') {
            throw new InvalidFactoryDefinition(sprintf(
                'The type "static" declared in %s cannot be used by a generated factory.',
                $context->getName(),
            ));
        }
        if ($lower === 'parent') {
            $parent = $context->getParentClass();
            if ($parent === false) {
                throw new InvalidFactoryDefinition(sprintf('%s declares "parent" without a parent class.', $context->getName()));
            }

            return '\\' . $parent->getName();
        }
        return in_array($lower, TypeCompatibility::BUILTIN_TYPES, true) ? $lower : '\\' . ltrim($name, '\\');
    }

    private function constantName(\ReflectionParameter $parameter): string
    {
        $name = (string) $parameter->getDefaultValueConstantName();
        $separator = strpos($name, '::');
        if ($separator === false) {
            return '\\' . ltrim($name, '\\');
        }
        $class = substr($name, 0, $separator);
        $constant = substr($name, $separator + 2);
        $declaring = $parameter->getDeclaringClass();
        if ($declaring !== null && in_array(strtolower($class), ['self', 'static'], true)) {
            $class = $declaring->getName();
        }

        return '\\' . ltrim($class, '\\') . '::' . $constant;
    }

    private function describe(\ReflectionParameter $parameter): string
    {
        $class = $parameter->getDeclaringClass();

        return sprintf(
            'Parameter $%s of %s%s()',
            $parameter->getName(),
            $class === null ? '' : $class->getName() . '::',
            $parameter->getDeclaringFunction()->getName(),
        );
    }
}
