<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The user the tool runs as.
 */
interface RuntimeUser
{
    /**
     * The effective user id of the running process.
     */
    public function effectiveUid(): int;
}
