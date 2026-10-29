<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Key;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates encryption keys; implemented by the container build.
 */
#[CreatesInstancesOf(Key::class)]
interface KeyFactory
{
    /**
     * @param string $raw the ring entry
     *
     * @throws InvalidKey when the entry is not a usable key
     */
    public function create(#[\SensitiveParameter] string $raw): Key;
}
