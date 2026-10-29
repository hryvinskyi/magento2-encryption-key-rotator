<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\DependencyInjection;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\Exception\InvalidFactoryDefinition;
use Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid\ExclamationMark;
use Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid\FarewellFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Fixtures\Factory\Valid\GreetingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\ContainerBuilder;

final class GeneratedFactoryPassTest extends TestCase
{
    private const FIXTURE_NAMESPACE = 'Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\';
    private const FIXTURE_DIRECTORY = __DIR__ . '/../../Fixtures/Factory';

    /**
     * One build directory for the whole class: a generated class is declared once per process, so
     * every build of the same factory in this process must load it from the same file.
     */
    private static string $buildDirectory;

    public static function setUpBeforeClass(): void
    {
        self::$buildDirectory = TemporaryDirectory::create('key-rotator-factory-pass');
    }

    public static function tearDownAfterClass(): void
    {
        TemporaryDirectory::remove(self::$buildDirectory);
    }

    public function testFactoryPassesRuntimeArgumentsAndAutowiredDependenciesToTheCreatedObject(): void
    {
        $container = $this->compile('valid', 'Valid');

        $factory = $container->get('fixture.greeting_factory');
        self::assertInstanceOf(GreetingFactory::class, $factory);
        $greeting = $factory->create('Ada', 2);

        self::assertSame('Ada', $greeting->name);
        self::assertSame(2, $greeting->times);
        self::assertInstanceOf(ExclamationMark::class, $greeting->punctuation);
        self::assertSame(' | ', $greeting->separator);
        self::assertSame('Hello Ada! | Hello Ada!', $greeting->text());
    }

    public function testEveryCallCreatesANewObjectWhileServicesAreShared(): void
    {
        $container = $this->compile('valid', 'Valid');
        $factory = $container->get('fixture.greeting_factory');
        self::assertInstanceOf(GreetingFactory::class, $factory);

        $first = $factory->createOnce('Ada');
        $second = $factory->createOnce('Grace');

        self::assertNotSame($first, $second);
        self::assertSame(1, $first->times);
        self::assertSame('Grace', $second->name);
        self::assertSame($first->punctuation, $second->punctuation);
    }

    public function testFactoryOfAnotherClassCreatesThatClass(): void
    {
        $container = $this->compile('valid', 'Valid');

        $factory = $container->get('fixture.farewell_factory');
        self::assertInstanceOf(FarewellFactory::class, $factory);
        $farewell = $factory->create('Ada');

        self::assertSame('Ada', $farewell->name);
    }

    public function testMethodParameterTheConstructorDoesNotHaveFailsTheBuild(): void
    {
        $this->expectException(InvalidFactoryDefinition::class);
        $this->expectExceptionMessageMatches(
            '/MissingParameter\\\\BadgeFactory::create\(\): parameter \$colour does not exist on the constructor of .*\\\\Badge\./',
        );

        $this->compile('missing-parameter', 'MissingParameter');
    }

    public function testMethodParameterTypeTheConstructorDoesNotAcceptFailsTheBuild(): void
    {
        $this->expectException(InvalidFactoryDefinition::class);
        $this->expectExceptionMessageMatches(
            '/TypeMismatch\\\\CounterFactory::create\(\): parameter \$start is declared "string", which the constructor of .*\\\\Counter does not accept as "int"\./',
        );

        $this->compile('type-mismatch', 'TypeMismatch');
    }

    public function testNonSharedServiceHandedToCreatedObjectsFailsTheBuild(): void
    {
        $this->expectException(InvalidFactoryDefinition::class);
        $this->expectExceptionMessageMatches(
            '/NonShared\\\\DocumentFactory: constructor parameter \$stamp \(not taken by create\(\)\) references the non-shared service ".*\\\\Stamp"/',
        );

        $this->compile('non-shared', 'NonShared');
    }

    public function testBuiltinConstructorParameterWithoutDefaultThatNoMethodTakesFailsTheBuild(): void
    {
        $this->expectException(InvalidFactoryDefinition::class);
        $this->expectExceptionMessageMatches(
            '/UnwirableScalar\\\\BatchFactory::create\(\) does not take constructor parameter \$size of .*\\\\Batch, and the container cannot supply it/',
        );

        $this->compile('unwirable-scalar', 'UnwirableScalar');
    }

    public function testNullableServiceParameterWithoutAMatchingServiceFailsInsteadOfReceivingNull(): void
    {
        $this->expectException(InvalidFactoryDefinition::class);
        $this->expectExceptionMessageMatches(
            '/UnwirableService\\\\MailerFactory: constructor parameter \$transport \(not taken by create\(\)\) would receive null/',
        );

        $this->compile('unwirable-service', 'UnwirableService');
    }

    public function testIdenticalFactoriesShareOneFileNameAndDifferentFactoriesDoNot(): void
    {
        $otherBuildDirectory = TemporaryDirectory::create('key-rotator-factory-pass-again');
        try {
            $this->compile('valid', 'Valid');
            $this->compile('valid', 'Valid', $otherBuildDirectory);

            $first = $this->generatedFileNames(self::$buildDirectory);
            $second = $this->generatedFileNames($otherBuildDirectory);
        } finally {
            TemporaryDirectory::remove($otherBuildDirectory);
        }

        self::assertCount(2, $second, 'Two factories, two generated files.');
        self::assertMatchesRegularExpression('/^Factory_[0-9a-f]{40}\.php$/', $second[0]);
        self::assertNotSame($second[0], $second[1]);
        self::assertSame([], array_diff($second, $first), 'The same factories are written under the same names.');
    }

    private function compile(string $config, string $case, ?string $buildDirectory = null): ContainerBuilder
    {
        $factory = new ContainerFactory(
            self::FIXTURE_DIRECTORY . '/config/' . $config . '.php',
            [self::FIXTURE_NAMESPACE . $case . '\\' => self::FIXTURE_DIRECTORY . '/' . $case],
        );

        return $factory->compile($buildDirectory ?? self::$buildDirectory);
    }

    /**
     * @return list<string>
     */
    private function generatedFileNames(string $directory): array
    {
        $files = glob($directory . '/Factory_*.php');
        self::assertIsArray($files);
        $names = array_map('basename', $files);
        sort($names);

        return $names;
    }
}
