<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Contract;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\RunStoreContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\DeploymentConfigServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\ScratchMagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\TemporaryDirectory;

/**
 * The run store on disk keeps the run store contract, with the real wiring, over a scratch state
 * directory outside a scratch Magento root.
 */
final class FilesystemRunStoreContractTest extends RunStoreContractTestCase
{
    /**
     * @var list<string>
     */
    private array $scratch = [];

    protected function tearDown(): void
    {
        foreach ($this->scratch as $directory) {
            TemporaryDirectory::remove($directory);
        }
    }

    protected function createStore(): RunStore
    {
        $services = DeploymentConfigServices::shared();
        $root = ScratchMagentoRoot::create(ScratchMagentoRoot::RETIRED_SLOT_AND_PREFIX);
        $state = TemporaryDirectory::create('key-rotator-state');
        $this->scratch[] = $root;
        $this->scratch[] = $state;
        $services->pointAtRoot($root);
        $services->pointAtStateDirectory($state . '/runs');

        return $services->freshRunStore();
    }

    protected function concurrentStore(RunStore $store): RunStore
    {
        return DeploymentConfigServices::shared()->freshRunStore();
    }
}
