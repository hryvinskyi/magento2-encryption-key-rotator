<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\MagentoRootProvider;

/**
 * The Magento root a test names.
 */
final class FixedMagentoRoot implements MagentoRootProvider
{
    public function __construct(
        private readonly MagentoRoot $root,
    ) {}

    public function root(): MagentoRoot
    {
        return $this->root;
    }
}
