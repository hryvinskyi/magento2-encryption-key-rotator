<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRoot;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\MagentoRootFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectMagentoRootFactory implements MagentoRootFactory
{
    public function create(string $path): MagentoRoot
    {
        return new MagentoRoot($path);
    }
}
