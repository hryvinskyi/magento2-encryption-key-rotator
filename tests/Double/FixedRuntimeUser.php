<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RuntimeUser;

/**
 * Runs as the user id a test gives it.
 */
final class FixedRuntimeUser implements RuntimeUser
{
    public function __construct(
        private readonly int $uid = 1000,
    ) {}

    public function effectiveUid(): int
    {
        return $this->uid;
    }
}
