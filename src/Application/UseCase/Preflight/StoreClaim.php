<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Preflight;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunClaimedElsewhere;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\RunRegistry;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StateDirectoryProvider;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;

/**
 * Keeps one unfinished run per Magento store, whatever state directory each run is kept in, through the
 * store's claim ({@see RunRegistry}):
 * - a rotation claims the store for its run before it writes anything, and claims it again whenever it
 *   resumes (a run started before the claim existed takes it then);
 * - the commands that continue a run refuse while the claim names another run;
 * - a purge gives the claim up, after the journal and before the run directory goes.
 *
 * A refusal names the run that holds the store and the state directory it is kept in, so the operator
 * knows where to finish it.
 */
final class StoreClaim
{
    public function __construct(
        private readonly RunRegistry $registry,
        private readonly StateDirectoryProvider $stateDirectory,
        private readonly RefusalFactory $refusals,
    ) {}

    /**
     * Claims the store for the run, kept in the command's state directory.
     *
     * @return Refusal|null why the run may not go on, or null once it holds the claim
     */
    public function claim(RunId $id): ?Refusal
    {
        try {
            $this->registry->claim($id, $this->stateDirectory->directory());
        } catch (RunClaimedElsewhere $claimed) {
            return $this->refusal($claimed->runId(), $claimed->stateDirectory());
        }

        return null;
    }

    /**
     * Refuses when the claim names another run than this one (any run, when there is none).
     */
    public function heldByAnother(?RunId $id): ?Refusal
    {
        $claim = $this->registry->claimed();
        if ($claim === null || ($id !== null && $claim['run_id'] === $id->toString())) {
            return null;
        }

        return $this->refusal($claim['run_id'], $claim['state_directory']);
    }

    public function release(RunId $id): void
    {
        $this->registry->release($id);
    }

    private function refusal(string $runId, string $stateDirectory): Refusal
    {
        $here = $stateDirectory === $this->stateDirectory->directory();

        return $this->refusals->create(RefusalReason::RunClaimedElsewhere, sprintf(
            'Run %s holds this store (one unfinished run per store) and is kept in %s%s. Finish it first: retire and purge it, or roll it back and purge it%s. Nothing was written.',
            $runId,
            $stateDirectory,
            $here ? ', this state directory' : '',
            $here ? '' : sprintf(' (pass --state-dir=%s)', $stateDirectory),
        ));
    }
}
