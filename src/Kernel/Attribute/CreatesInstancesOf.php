<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute;

/**
 * Marks an interface as a factory whose implementation the container build generates.
 *
 * Every method of the interface creates one instance of the named class: its parameters are passed by
 * name to that class's constructor, and the constructor parameters a method does not take are wired by
 * the container. Nobody writes the implementation by hand.
 */
#[\Attribute(\Attribute::TARGET_CLASS)]
final class CreatesInstancesOf
{
    /**
     * @param class-string $class the class every method of the factory creates
     */
    public function __construct(
        public readonly string $class,
    ) {}
}
