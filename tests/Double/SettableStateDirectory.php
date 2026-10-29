<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;

/**
 * The state directory of a container a test compiles once and points at a new scratch directory per
 * test, the way the command points the real provider at the directory it was given.
 */
final class SettableStateDirectory implements StateDirectoryProvider
{
    private ?string $directory = null;

    public function pointAt(string $directory): void
    {
        $this->directory = $directory;
    }

    public function directory(): string
    {
        return $this->directory ?? throw new \LogicException('The test has not pointed the provider at a state directory.');
    }
}
