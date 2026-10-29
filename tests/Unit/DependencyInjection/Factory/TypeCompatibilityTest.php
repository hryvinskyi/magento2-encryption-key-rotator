<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\DependencyInjection\Factory;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Factory\TypeCompatibility;
use Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid\ExclamationMark;
use Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid\Punctuation;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class TypeCompatibilityTest extends TestCase
{
    /**
     * @return iterable<string, array{\Closure, \Closure, bool}>
     */
    public static function pairs(): iterable
    {
        yield 'same builtin' => [static fn(int $v) => $v, static fn(int $v) => $v, true];
        yield 'int widens to float' => [static fn(float $v) => $v, static fn(int $v) => $v, true];
        yield 'float does not narrow to int' => [static fn(int $v) => $v, static fn(float $v) => $v, false];
        yield 'string is not int' => [static fn(int $v) => $v, static fn(string $v) => $v, false];
        yield 'nullable given, non-null declared' => [static fn(string $v) => $v, static fn(?string $v) => $v, false];
        yield 'non-null given, nullable declared' => [static fn(?string $v) => $v, static fn(string $v) => $v, true];
        yield 'implementation for its interface' => [static fn(Punctuation $v) => $v, static fn(ExclamationMark $v) => $v, true];
        yield 'interface for an implementation' => [static fn(ExclamationMark $v) => $v, static fn(Punctuation $v) => $v, false];
        yield 'class for object' => [static fn(object $v) => $v, static fn(ExclamationMark $v) => $v, true];
        yield 'array for iterable' => [static fn(iterable $v) => $v, static fn(array $v) => $v, true];
        yield 'iterable for array' => [static fn(array $v) => $v, static fn(iterable $v) => $v, false];
        yield 'untyped declared accepts anything' => [static fn($v) => $v, static fn(int $v) => $v, true];
        yield 'untyped given for typed declared' => [static fn(int $v) => $v, static fn($v) => $v, false];
        yield 'mixed declared accepts untyped' => [static fn(mixed $v) => $v, static fn($v) => $v, true];
        yield 'union inside wider union' => [static fn(int|string|null $v) => $v, static fn(int|string $v) => $v, true];
        yield 'union for one member' => [static fn(int $v) => $v, static fn(int|string $v) => $v, false];
        yield 'false for bool' => [static fn(bool $v) => $v, static fn(false|int $v) => $v, false];
        yield 'bool for bool or int' => [static fn(bool|int $v) => $v, static fn(bool $v) => $v, true];
    }

    #[DataProvider('pairs')]
    public function testAcceptsOnlyWhatTheDeclaredTypeAlwaysTakes(\Closure $declared, \Closure $given, bool $expected): void
    {
        $context = new \ReflectionClass(self::class);

        self::assertSame($expected, (new TypeCompatibility())->accepts(
            $this->firstParameterType($declared),
            $context,
            $this->firstParameterType($given),
            $context,
        ));
    }

    public function testInstanceOfAClassSatisfiesItsInterfaceButNotAnUnrelatedType(): void
    {
        $context = new \ReflectionClass(self::class);
        $types = new TypeCompatibility();

        self::assertTrue($types->acceptsInstanceOf($this->returnType(static fn(): Punctuation => new ExclamationMark()), $context, ExclamationMark::class));
        self::assertFalse($types->acceptsInstanceOf($this->returnType(static fn(): string => ''), $context, ExclamationMark::class));
        self::assertFalse($types->acceptsInstanceOf(null, $context, ExclamationMark::class), 'A missing return type is refused.');
    }

    public function testOnlyClassTypesCountAsWirable(): void
    {
        $context = new \ReflectionClass(self::class);
        $types = new TypeCompatibility();

        self::assertTrue($types->namesOnlyClasses($this->firstParameterType(static fn(?Punctuation $v) => $v), $context));
        self::assertFalse($types->namesOnlyClasses($this->firstParameterType(static fn(int $v) => $v), $context));
        self::assertFalse($types->namesOnlyClasses($this->firstParameterType(static fn(Punctuation|string $v) => $v), $context));
        self::assertFalse($types->namesOnlyClasses(null, $context));
    }

    private function firstParameterType(\Closure $function): ?\ReflectionType
    {
        return (new \ReflectionFunction($function))->getParameters()[0]->getType();
    }

    private function returnType(\Closure $function): ?\ReflectionType
    {
        return (new \ReflectionFunction($function))->getReturnType();
    }
}
