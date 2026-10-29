<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;

/**
 * The Magento root of a container a test compiles once and points at a new scratch root per test, the
 * way the command points the real provider at the root it was given.
 */
final class SettableMagentoRoot implements MagentoRootProvider
{
    private ?MagentoRoot $root = null;

    public function pointAt(MagentoRoot $root): void
    {
        $this->root = $root;
    }

    public function root(): MagentoRoot
    {
        return $this->root ?? throw new \LogicException('The test has not pointed the provider at a Magento root.');
    }
}
