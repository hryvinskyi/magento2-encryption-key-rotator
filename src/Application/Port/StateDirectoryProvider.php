<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The directory the runs of the command's Magento root are kept under: the one the command was given,
 * or `<Magento root>/var/encryption-key-rotation` by default. Known only once the command has read its
 * options.
 */
interface StateDirectoryProvider
{
    /**
     * The absolute path of the state directory; it may not exist yet.
     */
    public function directory(): string;
}
