<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\DeploymentConfigRenderer;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Magento\NestedArray;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\DeploymentConfigWriterContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;

/**
 * The adapter that writes `app/etc/env.php` keeps the deployment configuration writer contract, on a
 * scratch Magento root whose file is rendered in the store's own format.
 */
final class EnvPhpDeploymentConfigWriterTest extends DeploymentConfigWriterContractTestCase
{
    private ?string $root = null;

    protected function tearDown(): void
    {
        if ($this->root !== null) {
            TemporaryDirectory::remove($this->root);
        }
    }

    protected function seed(string $cryptKey, array $systemValues): void
    {
        $system = [];
        $tree = new NestedArray();
        foreach ($systemValues as $value) {
            $system = $tree->with($system, $value['path'], $value['value']);
        }

        $services = DeploymentConfigServices::shared();
        $this->root = TemporaryDirectory::create('key-rotator-contract-root');
        mkdir($this->root . '/app/etc', 0755, true);
        $php = $services->get(DeploymentConfigRenderer::class)->render([
            'crypt' => ['key' => $cryptKey],
            'db' => ['table_prefix' => '', 'connection' => ['default' => ['host' => 'db', 'dbname' => 'store', 'username' => 'store', 'password' => '']]],
            'system' => $system,
        ]);
        file_put_contents($this->root . '/app/etc/env.php', $php);
        $services->pointAtRoot($this->root);
    }

    protected function reader(): DeploymentConfigReader
    {
        return DeploymentConfigServices::shared()->get(DeploymentConfigReader::class);
    }

    protected function writer(): DeploymentConfigWriter
    {
        return DeploymentConfigServices::shared()->get(DeploymentConfigWriter::class);
    }
}
