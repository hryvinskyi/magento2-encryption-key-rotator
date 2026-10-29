<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SettableMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SettableStateDirectory;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * The configuration-file and run-store adapters exactly as the tool's real container builds them,
 * generated factories included, pointed at the scratch Magento root and state directory of the
 * running test.
 *
 * The container is compiled once per process, into a scratch directory removed when the process ends.
 */
final class DeploymentConfigServices
{
    private static ?self $shared = null;

    private function __construct(
        private readonly ContainerInterface $container,
    ) {}

    public static function shared(): self
    {
        if (self::$shared !== null) {
            return self::$shared;
        }

        $buildDirectory = TemporaryDirectory::create('key-rotator-deployment-config-services');
        register_shutdown_function(static function () use ($buildDirectory): void {
            TemporaryDirectory::remove($buildDirectory);
        });
        $root = dirname(__DIR__, 2);
        $container = (new ContainerFactory(
            $root . '/tests/Fixtures/Container/deployment-config-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile($buildDirectory);

        return self::$shared = new self($container);
    }

    /**
     * Points every adapter at the Magento root (a directory holding `app/etc/env.php`).
     */
    public function pointAtRoot(string $path): void
    {
        $this->service(SettableMagentoRoot::class, SettableMagentoRoot::class)
            ->pointAt($this->get(MagentoRootFactory::class)->create($path));
    }

    /**
     * Points every run store at the state directory.
     */
    public function pointAtStateDirectory(string $path): void
    {
        $this->service(SettableStateDirectory::class, SettableStateDirectory::class)->pointAt($path);
    }

    /**
     * A new run store with the real wiring, as another process opening the same directory holds.
     */
    public function freshRunStore(): RunStore
    {
        return $this->service('test.fresh.run_store', RunStore::class);
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
        return $this->service('test.' . $id, $id);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $type
     *
     * @return T
     */
    private function service(string $id, string $type): object
    {
        $service = $this->container->get($id);
        if (!$service instanceof $type) {
            throw new \LogicException(sprintf('The container holds no %s as "%s".', $type, $id));
        }

        return $service;
    }
}
