<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;
use PHPUnit\Framework\TestCase;

final class MagentoRootTest extends TestCase
{
    private string $directory;

    protected function setUp(): void
    {
        $this->directory = TemporaryDirectory::create('key-rotator-root');
    }

    protected function tearDown(): void
    {
        TemporaryDirectory::remove($this->directory);
    }

    public function testARootHoldsTheDeploymentConfiguration(): void
    {
        mkdir($this->directory . '/app/etc', 0700, true);
        touch($this->directory . '/app/etc/env.php');

        $root = new MagentoRoot($this->directory . '/');

        self::assertSame($this->directory, $root->path());
        self::assertSame($this->directory . '/app/etc/env.php', $root->deploymentConfigFile());
        self::assertSame($this->directory . '/app/etc/config.php', $root->committedConfigFile());
        self::assertSame($this->directory . '/bin/magento', $root->file('bin/magento'));
    }

    public function testADirectoryWithoutTheDeploymentConfigurationIsRefused(): void
    {
        $this->expectException(InvalidMagentoRoot::class);
        $this->expectExceptionMessage('app/etc/env.php');

        new MagentoRoot($this->directory);
    }

    public function testARelativePathIsRefused(): void
    {
        $this->expectException(InvalidMagentoRoot::class);
        $this->expectExceptionMessage('absolute');

        new MagentoRoot('magento');
    }
}
