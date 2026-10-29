<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Contract\InMemory;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Tests\Contract\RunRegistryContractTestCase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryRunRegistry;

/**
 * The in-memory registry keeps the run registry contract. Every process of the store shares the one
 * instance, as they share the store's table.
 */
final class InMemoryRunRegistryTest extends RunRegistryContractTestCase
{
    private ?InMemoryRunRegistry $registry = null;

    protected function registry(): RunRegistry
    {
        return $this->registry ??= new InMemoryRunRegistry();
    }

    protected function otherProcess(): RunRegistry
    {
        return $this->registry();
    }
}
