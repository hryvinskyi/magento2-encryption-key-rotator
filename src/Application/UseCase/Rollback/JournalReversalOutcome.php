<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rollback;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\Conflict;

/**
 * What undoing a run's forward journal did:
 * - the values put back to their exact bytes from before the run;
 * - the values the store rewrote under the new key after the run moved them, re-encrypted onto the key
 *   that was active before the run, their forward entries settled in the same transaction;
 * - the entries left alone: their row holds something else now (another key, a plain value, nothing),
 *   so the store's newer value is kept; they stay pending and are reported again on the next rollback.
 *
 * Created through {@see JournalReversalOutcomeFactory}.
 */
final class JournalReversalOutcome
{
    /**
     * @param int            $reverted   values put back to their bytes from before the run
     * @param int            $superseded values the store rewrote under the new key, moved onto the old active key
     * @param list<Conflict> $leftAlone  the rows whose entries stay pending
     */
    public function __construct(
        private readonly int $reverted,
        private readonly int $superseded,
        private readonly array $leftAlone,
    ) {}

    public function reverted(): int
    {
        return $this->reverted;
    }

    public function superseded(): int
    {
        return $this->superseded;
    }

    /**
     * @return list<Conflict>
     */
    public function leftAlone(): array
    {
        return $this->leftAlone;
    }
}
