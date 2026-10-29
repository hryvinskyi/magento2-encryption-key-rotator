<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli;

use Hryvinskyi\EncryptionKeyRotator\Cli\Context\CommandContext;
use Hryvinskyi\EncryptionKeyRotator\Cli\ExitCode;
use Hryvinskyi\EncryptionKeyRotator\Cli\Option\CommandOptions;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectMagentoRootFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanScopeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Cli\Support\CliWorld;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Input\InputInterface;
use Symfony\Component\Console\Output\OutputInterface;

/**
 * The command context is empty until a command starts, and the context listener fills it from the
 * command's options before the command runs: only the options the command defines.
 */
final class CommandContextTest extends TestCase
{
    private ?CliWorld $cli = null;

    protected function tearDown(): void
    {
        $this->cli?->cleanUp();
    }

    public function testReadingTheContextBeforeACommandStartedFailsLoudly(): void
    {
        $context = new CommandContext();

        foreach ([
            static fn() => $context->root(),
            static fn() => $context->directory(),
            static fn() => $context->settings(),
        ] as $read) {
            try {
                $read();
                self::fail('The empty context answered.');
            } catch (\LogicException $empty) {
                self::assertStringContainsString('not known', $empty->getMessage());
            }
        }
    }

    public function testTheListenerFillsTheContextBeforeTheCommandRuns(): void
    {
        $seen = [];
        $this->cli = $cli = new CliWorld([$this->command('store-and-probe', static function (CommandOptions $options, Command $command): void {
            $options->addStoreOptions($command);
            $options->addProbeOptions($command);
        }, static function () use (&$seen, &$cli): void {
            $seen = [$cli?->context->root()->path(), $cli?->context->directory(), $cli?->context->settings()->fastCgiAddress()];
        })]);
        $state = $cli->world->root . '/../elsewhere';

        $tester = $cli->run(['command' => 'store-and-probe', '--state-dir' => $state, '--probe-fcgi' => 'tcp://127.0.0.1:9000']);

        self::assertSame(0, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertSame([$cli->world->root, $state, 'tcp://127.0.0.1:9000'], $seen);
    }

    public function testTheStateDirectoryDefaultsToOneInsideTheRootAndARelativeRootIsTheCurrentDirectorysChild(): void
    {
        $this->cli = $cli = new CliWorld([$this->command('store-only', static function (CommandOptions $options, Command $command): void {
            $options->addStoreOptions($command);
        })]);
        $previous = getcwd();
        self::assertIsString($previous);
        chdir(dirname($cli->world->root));
        try {
            $tester = $cli->run(['command' => 'store-only', '--magento-root' => basename($cli->world->root)]);
        } finally {
            chdir($previous);
        }

        self::assertSame(0, $tester->getStatusCode(), CliWorld::everything($tester));
        self::assertSame(realpath($cli->world->root), realpath($cli->context->root()->path()));
        self::assertSame($cli->context->root()->path() . '/var/encryption-key-rotation', $cli->context->directory());
        $this->expectException(\LogicException::class);
        $cli->context->settings();
    }

    public function testARootWithoutTheDeploymentConfigurationIsRefusedBeforeTheCommandRuns(): void
    {
        $ran = false;
        $this->cli = $cli = new CliWorld([$this->command('store-only', static function (CommandOptions $options, Command $command): void {
            $options->addStoreOptions($command);
        }, static function () use (&$ran): void {
            $ran = true;
        })]);

        $tester = $cli->run(['command' => 'store-only', '--magento-root' => $cli->world->root . '/pub']);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('--magento-root', $tester->getErrorOutput());
        self::assertFalse($ran);
    }

    public function testAProbeWaitThatIsNoNumberIsRefused(): void
    {
        $this->cli = $cli = new CliWorld();

        $tester = $cli->run(['command' => 'rotate', '--yes' => true, '--skip-web-probe' => true, '--probe-wait' => 'soon']);

        self::assertSame(ExitCode::REFUSED, $tester->getStatusCode());
        self::assertStringContainsString('--probe-wait', $tester->getErrorOutput());
    }

    public function testACommandWithoutTheStoreOptionsLeavesTheContextEmpty(): void
    {
        $this->cli = $cli = new CliWorld([$this->command('plain', static function (): void {})]);

        self::assertSame(0, $cli->run(['command' => 'plain'])->getStatusCode());
        $this->expectException(\LogicException::class);
        $cli->context->root();
    }

    /**
     * @param \Closure(CommandOptions, Command): void $configure
     * @param (\Closure(): void)|null                $execute
     */
    private function command(string $name, \Closure $configure, ?\Closure $execute = null): Command
    {
        return new class ($name, $configure, $execute ?? static function (): void {}) extends Command {
            /**
             * @param \Closure(CommandOptions, Command): void $configureOptions
             * @param \Closure(): void                       $run
             */
            public function __construct(string $name, private readonly \Closure $configureOptions, private readonly \Closure $run)
            {
                parent::__construct($name);
            }

            protected function configure(): void
            {
                ($this->configureOptions)(
                    new CommandOptions(
                        new DirectMagentoRootFactory(),
                        new DirectProbeSettingsFactory(),
                        new DirectScanScopeFactory(),
                    ),
                    $this,
                );
            }

            protected function execute(InputInterface $input, OutputInterface $output): int
            {
                ($this->run)();

                return 0;
            }
        };
    }
}
