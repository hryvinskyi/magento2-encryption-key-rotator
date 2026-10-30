<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * Prepares the store's database to hold the journal.
 */
interface JournalSchema
{
    /**
     * Creates the journal when it does not exist, and brings one an earlier release created to the
     * current shape; the entries it holds stay as they are.
     */
    public function ensure(): void;
}
