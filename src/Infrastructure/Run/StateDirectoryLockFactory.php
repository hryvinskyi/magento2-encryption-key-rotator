<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates the lock holder of a run store, one per store; implemented by the container build.
 */
#[CreatesInstancesOf(StateDirectoryLock::class)]
interface StateDirectoryLockFactory
{
    public function create(): StateDirectoryLock;
}
