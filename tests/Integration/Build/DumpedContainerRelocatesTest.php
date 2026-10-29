<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\DependencyInjection\ContainerFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Process\Process;

final class DumpedContainerRelocatesTest extends TestCase
{
    private string $scratch;

    protected function setUp(): void
    {
        $this->scratch = TemporaryDirectory::create('key-rotator-relocation');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->scratch);
    }

    public function testAMovedBuildDirectoryStillLoadsItsGeneratedFactories(): void
    {
        $fixtures = dirname(__DIR__, 2) . '/Fixtures/Factory';
        $buildDirectory = $this->scratch . '/built-here/out';
        $bootstrapFile = (new ContainerFactory(
            $fixtures . '/config/valid.php',
            ['Hryvinskyi\\EncryptionKeyRotator\\Tests\\Fixtures\\Factory\\Valid\\' => $fixtures . '/Valid'],
        ))->dump($buildDirectory);
        self::assertNotEmpty(glob($buildDirectory . '/Factory_*.php'));

        mkdir($this->scratch . '/moved-there');
        $movedDirectory = $this->scratch . '/moved-there/out';
        self::assertTrue(rename($buildDirectory, $movedDirectory));
        self::assertDirectoryDoesNotExist($buildDirectory);

        $script = <<<'PHP'
            require $argv[1];
            $container = require $argv[2];
            echo $container->get('fixture.greeting_factory')->create('Ada', 2)->text();
            PHP;
        $process = new Process([
            PHP_BINARY,
            '-r',
            $script,
            dirname(__DIR__, 3) . '/vendor/autoload.php',
            $movedDirectory . '/' . basename($bootstrapFile),
        ]);
        $process->run();

        self::assertTrue($process->isSuccessful(), $process->getErrorOutput() . $process->getOutput());
        self::assertSame('Hello Ada! | Hello Ada!', $process->getOutput());
    }
}
