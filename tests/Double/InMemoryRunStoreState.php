<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double;

/**
 * What an {@see InMemoryRunStore} keeps, shared by every handle onto the same state directory, the way
 * two processes share one directory on disk.
 *
 * @internal used by the in-memory run store only
 */
final class InMemoryRunStoreState
{
    /**
     * @var array<string, string> run id => JSON of the run's snapshot, in the order runs were first saved
     */
    public array $runs = [];

    /**
     * @var array<string, array<string, array<int, string>>> run id => role => index => kept ring entry
     */
    public array $keys = [];

    /**
     * @var array<string, array<int, string>> run id => index => kept placeholder
     */
    public array $placeholders = [];

    /**
     * @var array<string, int> run id => number of deployment configuration backups taken
     */
    public array $backups = [];

    /**
     * The handle holding the lock, or null when none does.
     */
    public ?object $lockHolder = null;
}
