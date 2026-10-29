<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see MagentoRoot} values; implemented by the container build.
 */
#[CreatesInstancesOf(MagentoRoot::class)]
interface MagentoRootFactory
{
    /**
     * @throws InvalidMagentoRoot when the path is not absolute or holds no `app/etc/env.php`
     */
    public function create(string $path): MagentoRoot;
}
