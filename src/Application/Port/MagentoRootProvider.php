<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;

/**
 * The Magento root the running command works on, known only once the command has read its options.
 * Every adapter that touches the store's files or runs its commands asks this port, at the moment it
 * needs the root, never in its constructor.
 */
interface MagentoRootProvider
{
    public function root(): MagentoRoot;
}
