<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory;

/**
 * Decides whether a value of one declared type is always accepted by another declared type.
 *
 * A factory method parameter is compatible with the constructor parameter of the same name when every
 * value the method accepts is a value the constructor accepts under strict types. Types are compared as
 * sets of atoms: a union is its members, an intersection is one atom made of several classes, and a
 * nullable type adds `null`.
 */
final class TypeCompatibility
{
    /**
     * The type names PHP reserves; every other name in a type declaration is a class or an interface.
     */
    public const BUILTIN_TYPES = [
        'array', 'bool', 'callable', 'false', 'float', 'int', 'iterable', 'mixed', 'never', 'null',
        'object', 'string', 'true', 'void',
    ];

    /**
     * @param \ReflectionClass<object> $declaredIn the class that declares `$declared` (resolves `self`)
     * @param \ReflectionClass<object> $givenIn    the class that declares `$given` (resolves `self`)
     */
    public function accepts(
        ?\ReflectionType $declared,
        \ReflectionClass $declaredIn,
        ?\ReflectionType $given,
        \ReflectionClass $givenIn,
    ): bool {
        if ($declared === null) {
            return true;
        }
        $declaredAtoms = $this->atoms($declared, $declaredIn);
        $givenAtoms = $given === null ? [['mixed']] : $this->atoms($given, $givenIn);

        foreach ($givenAtoms as $givenAtom) {
            if (!$this->anyAtomAccepts($declaredAtoms, $givenAtom)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Whether an instance of `$class` satisfies the declared type (a factory method's return type).
     *
     * @param \ReflectionClass<object> $declaredIn
     */
    public function acceptsInstanceOf(?\ReflectionType $declared, \ReflectionClass $declaredIn, string $class): bool
    {
        if ($declared === null) {
            return false;
        }

        return $this->anyAtomAccepts($this->atoms($declared, $declaredIn), [$class]);
    }

    /**
     * Whether every member of the type names a class or an interface (something a container wires).
     *
     * @param \ReflectionClass<object> $declaredIn
     */
    public function namesOnlyClasses(?\ReflectionType $type, \ReflectionClass $declaredIn): bool
    {
        if ($type === null) {
            return false;
        }
        foreach ($this->atoms($type, $declaredIn) as $atom) {
            foreach ($atom as $name) {
                if ($name !== 'null' && !$this->isClass($name)) {
                    return false;
                }
            }
        }

        return true;
    }

    /**
     * @param \ReflectionClass<object> $context
     *
     * @return list<list<string>>
     */
    private function atoms(\ReflectionType $type, \ReflectionClass $context): array
    {
        if ($type instanceof \ReflectionNamedType) {
            $name = $this->normalise($type->getName(), $context);
            $atoms = [[$name]];
            if ($type->allowsNull() && $name !== 'null' && $name !== 'mixed') {
                $atoms[] = ['null'];
            }

            return $atoms;
        }
        if ($type instanceof \ReflectionIntersectionType) {
            return [$this->intersectionNames($type, $context)];
        }
        if ($type instanceof \ReflectionUnionType) {
            $atoms = [];
            foreach ($type->getTypes() as $member) {
                $atoms[] = $member instanceof \ReflectionIntersectionType
                    ? $this->intersectionNames($member, $context)
                    : [$this->normalise($member->getName(), $context)];
            }

            return $atoms;
        }

        return [['mixed']];
    }

    /**
     * @param \ReflectionClass<object> $context
     *
     * @return list<string>
     */
    private function intersectionNames(\ReflectionIntersectionType $type, \ReflectionClass $context): array
    {
        $names = [];
        foreach ($type->getTypes() as $member) {
            if ($member instanceof \ReflectionNamedType) {
                $names[] = $this->normalise($member->getName(), $context);
            }
        }

        return $names;
    }

    /**
     * @param list<list<string>> $declaredAtoms
     * @param list<string>       $givenAtom
     */
    private function anyAtomAccepts(array $declaredAtoms, array $givenAtom): bool
    {
        foreach ($declaredAtoms as $declaredAtom) {
            if ($this->atomAccepts($declaredAtom, $givenAtom)) {
                return true;
            }
        }

        return false;
    }

    /**
     * An atom accepts a value when every one of its names is satisfied by the given atom.
     *
     * @param list<string> $declared
     * @param list<string> $given
     */
    private function atomAccepts(array $declared, array $given): bool
    {
        foreach ($declared as $declaredName) {
            $satisfied = false;
            foreach ($given as $givenName) {
                if ($this->nameAccepts($declaredName, $givenName)) {
                    $satisfied = true;
                    break;
                }
            }
            if (!$satisfied) {
                return false;
            }
        }

        return true;
    }

    private function nameAccepts(string $declared, string $given): bool
    {
        if (strcasecmp($declared, $given) === 0 || $declared === 'mixed') {
            return true;
        }
        $givenIsClass = $this->isClass($given);

        return match ($declared) {
            'float' => $given === 'int',
            'bool' => $given === 'true' || $given === 'false',
            'iterable' => $given === 'array' || ($givenIsClass && is_a($given, \Traversable::class, true)),
            'object' => $givenIsClass,
            'callable' => $givenIsClass && is_a($given, \Closure::class, true),
            default => $givenIsClass && $this->isClass($declared) && is_a($given, $declared, true),
        };
    }

    /**
     * @param \ReflectionClass<object> $context
     */
    private function normalise(string $name, \ReflectionClass $context): string
    {
        $lower = strtolower($name);
        if ($lower === 'self' || $lower === 'static') {
            return $context->getName();
        }
        if ($lower === 'parent') {
            $parent = $context->getParentClass();

            return $parent === false ? $name : $parent->getName();
        }

        return in_array($lower, self::BUILTIN_TYPES, true) ? $lower : ltrim($name, '\\');
    }

    private function isClass(string $name): bool
    {
        return !in_array($name, self::BUILTIN_TYPES, true);
    }
}
