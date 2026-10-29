<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;

/**
 * The state directory a test names.
 */
final class FixedStateDirectory implements StateDirectoryProvider
{
    public function __construct(
        private readonly string $directory,
    ) {}

    public function directory(): string
    {
        return $this->directory;
    }
}
