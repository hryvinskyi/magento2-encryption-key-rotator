<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Cli;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Cli\ConsoleApplication;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\Nested;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Tester\ApplicationTester;
use Symfony\Component\DependencyInjection\ContainerInterface;

/**
 * Through the compiled container: the console application announces every command on the dispatcher the
 * context listener is subscribed to, so the adapters the container built before any command ran see the
 * Magento root and the state directory the command was given. The application, its commands and every
 * service behind them are resolved before the root even exists, which proves none of them reads it early.
 */
final class ContextListenerTest extends TestCase
{
    private string $buildDirectory;

    private ?string $root = null;

    private string $stateDirectory;

    protected function setUp(): void
    {
        $this->buildDirectory = TemporaryDirectory::create('key-rotator-cli-container');
        $this->stateDirectory = TemporaryDirectory::create('key-rotator-cli-state');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->buildDirectory);
        TemporaryDirectory::remove($this->stateDirectory);
        if ($this->root !== null) {
            TemporaryDirectory::remove($this->root);
        }
    }

    public function testACommandsOptionsReachTheAdaptersTheContainerBuiltBeforeIt(): void
    {
        $container = $this->container();
        $application = $container->get(Application::class);
        self::assertInstanceOf(ConsoleApplication::class, $application);
        foreach (['scan', 'rotate', 'status', 'retire', 'rollback', 'purge'] as $command) {
            self::assertTrue($application->has($command), $command);
            $application->find($command);
        }
        $config = $this->service($container, DeploymentConfigReader::class);
        $runs = $this->service($container, RunStore::class);

        $this->root = ScratchMagentoRoot::create(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $application->setAutoExit(false);
        $tester = new ApplicationTester($application);
        $tester->run(
            ['command' => 'status', '--magento-root' => $this->root, '--state-dir' => $this->stateDirectory, '--format' => 'json'],
            ['capture_stderr_separately' => true],
        );

        self::assertSame(ExitCode::DONE, $tester->getStatusCode(), $tester->getDisplay() . $tester->getErrorOutput());
        self::assertSame($this->root, $this->service($container, MagentoRootProvider::class)->root()->path());
        self::assertSame($this->stateDirectory, $this->service($container, StateDirectoryProvider::class)->directory());
        $expected = CryptoServices::shared()->ringParser()->parse(Nested::string(ScratchMagentoRoot::evaluate($this->root . '/app/etc/env.php'), 'crypt', 'key'));
        self::assertSame($expected->fingerprint(), $config->keyRing()->fingerprint());
        self::assertNull($runs->latest());
        self::assertSame('m2_', $config->databaseSettings()->tablePrefix());
    }

    public function testARootWithoutTheDeploymentConfigurationIsRefusedThroughTheRealWiring(): void
    {
        $application = $this->container()->get(Application::class);
        self::assertInstanceOf(ConsoleApplication::class, $application);
        $application->setAutoExit(false);
        $tester = new ApplicationTester($application);

        $tester->run(['command' => 'scan', '--magento-root' => $this->stateDirectory], ['capture_stderr_separately' => true]);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('--magento-root', $tester->getErrorOutput());
    }

    private function container(): ContainerInterface
    {
        $repository = dirname(__DIR__, 3);

        return (new ContainerFactory(
            $repository . '/tests/Fixtures/Container/cli-services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $repository . '/src'],
        ))->compile($this->buildDirectory);
    }

    /**
     * @template T of object
     *
     * @param class-string<T> $id
     *
     * @return T
     */
    private function service(ContainerInterface $container, string $id): object
    {
        $service = $container->get('test.' . $id);
        self::assertInstanceOf($id, $service);

        return $service;
    }
}
