<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Prepares the store's database to hold the journal.
 */
interface JournalSchema
{
    /**
     * Creates the journal when it does not exist; leaves an existing one as it is.
     */
    public function ensure(): void;
}
