<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Cli\AboutCommand;
use Hryvinskyi\EncryptionKeyRotator\Cli\ConsoleApplication;
use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Console\Application;
use Symfony\Component\Console\Command\Command;
use Symfony\Component\Console\Tester\CommandTester;

final class ContainerCompilesTest extends TestCase
{
    private string $buildDirectory;

    protected function setUp(): void
    {
        $this->buildDirectory = TemporaryDirectory::create('key-rotator-container');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->buildDirectory);
    }

    public function testTheRealContainerProvidesTheConsoleApplicationWithTheAboutCommand(): void
    {
        $root = dirname(__DIR__, 3);
        $container = (new ContainerFactory(
            $root . '/config/services.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\' => $root . '/src'],
        ))->compile($this->buildDirectory);

        $application = $container->get(Application::class);

        self::assertInstanceOf(ConsoleApplication::class, $application);
        self::assertSame(ConsoleApplication::NAME, $application->getName());
        self::assertTrue($application->has('about'));
        $about = $application->find('about');
        self::assertInstanceOf(AboutCommand::class, $about);

        $tester = new CommandTester($about);
        self::assertSame(Command::SUCCESS, $tester->execute([]), $tester->getDisplay());
        self::assertStringContainsString('PHP: ' . PHP_VERSION, $tester->getDisplay());
    }
}
