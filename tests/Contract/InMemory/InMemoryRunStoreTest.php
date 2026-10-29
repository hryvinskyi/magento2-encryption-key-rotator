<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract\InMemory;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunStore;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\RunStoreContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryRunStore;

/**
 * The in-memory run store keeps the run store contract.
 */
final class InMemoryRunStoreTest extends RunStoreContractTestCase
{
    protected function createStore(): RunStore
    {
        return new InMemoryRunStore();
    }

    protected function concurrentStore(RunStore $store): RunStore
    {
        if (!$store instanceof InMemoryRunStore) {
            throw new \LogicException('This contract subclass opens in-memory stores only.');
        }

        return $store->concurrentHandle();
    }
}
