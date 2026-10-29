<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract\InMemory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigWriter;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\CiphertextParser;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRingParser;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\DeploymentConfigWriterContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectCiphertextFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyRingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeySlotFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;

/**
 * The in-memory deployment configuration keeps the deployment configuration writer contract.
 */
final class InMemoryDeploymentConfigWriterTest extends DeploymentConfigWriterContractTestCase
{
    private ?InMemoryDeploymentConfig $config = null;

    protected function seed(string $cryptKey, array $systemValues): void
    {
        $ring = (new KeyRingParser(new DirectKeySlotFactory(), new DirectKeyRingFactory()))->parse($cryptKey);
        $parser = new CiphertextParser(new DirectCiphertextFactory());
        $values = [];
        foreach ($systemValues as $value) {
            $ciphertext = $parser->parse($value['value']) ?? throw new \LogicException('A seeded system value is a ciphertext.');
            $values[] = new SystemValue($value['path'], $ciphertext, SystemValueSource::Env);
        }
        $this->config = new InMemoryDeploymentConfig($ring, $values);
    }

    protected function reader(): DeploymentConfigReader
    {
        return $this->config();
    }

    protected function writer(): DeploymentConfigWriter
    {
        return $this->config();
    }

    private function config(): InMemoryDeploymentConfig
    {
        return $this->config ?? throw new \LogicException('The configuration is seeded in setUp.');
    }
}
