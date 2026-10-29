<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Holds, in the store itself, which run may change its keys: one unfinished run per Magento store,
 * whatever state directory each run keeps its files in. The lock and the run files of a state directory
 * only see the runs of that directory; this claim is seen by every run of the store.
 *
 * A run claims the store before it writes anything and keeps the claim until it is purged; a rolled-back
 * or retired run therefore still holds it, since its kept material is what undoing or finishing it needs.
 */
interface RunRegistry
{
    /**
     * Claims the store for the run; claiming it again for the run that holds it changes nothing.
     *
     * @param string $stateDirectory where the run keeps its files, so a refusal can tell an operator where to look
     *
     * @throws RunClaimedElsewhere when another run holds the claim
     */
    public function claim(RunId $id, string $stateDirectory): void;

    /**
     * @return array{run_id: string, state_directory: string}|null the run that holds the claim and where it keeps its files, or null when none does
     */
    public function claimed(): ?array;

    /**
     * Gives the claim up, when the run holds it; a claim of another run is left as it is.
     */
    public function release(RunId $id): void;
}
