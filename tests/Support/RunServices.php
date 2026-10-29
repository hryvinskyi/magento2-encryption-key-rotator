<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The run services and the factories of port values exactly as the tool's real container builds them,
 * generated factories included, for tests that must exercise the shipped wiring rather than test
 * doubles.
 *
 * The container is compiled once per process, into a scratch directory removed when the process ends.
 */
final class RunServices
{
    private static ?self $shared = null;

    private function __construct(
        private readonly ContainerInterface $container,
    ) {}

    /**
     * The services of the real service configuration, compiled on first use.
     */
    public static function shared(): self
    {
        if (self::$shared !== null) {
            return self::$shared;
        }

        $buildDirectory = TemporaryDirectory::create('key-rotator-run-services');
        register_shutdown_function(static function () use ($buildDirectory): void {
            TemporaryDirectory::remove($buildDirectory);
        });
        $root = dirname(__DIR__, 2);
        $container = (new ContainerFactory(
            $root . '/tests/Fixtures/Container/run-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile($buildDirectory);

        return self::$shared = new self($container);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id an interface or class the fixture configuration aliases for tests
     *
     * @return T
     */
    public function get(string $id): object
    {
        $service = $this->container->get('test.' . $id);
        if (!$service instanceof $id) {
            throw new \LogicException(sprintf('The container holds no %s.', $id));
        }

        return $service;
    }
}
