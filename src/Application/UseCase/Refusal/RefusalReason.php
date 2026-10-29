<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal;

/**
 * Why a writing command refused to go on. Every reason is a safety check, not an error: nothing was
 * written past the point the check guards, and the command can be run again once the cause is gone.
 */
enum RefusalReason: string
{
    /** The deployment configuration holds another key ring than the run expects: another writer changed it. */
    case RingChanged = 'ring_changed';

    /** The key ring of the deployment configuration cannot be read as a ring of usable keys. */
    case RingUnusable = 'ring_unusable';

    /** The deployment configuration holds more than literal data, so rewriting it would bake in values of the environment. */
    case DeploymentConfigNotLiteral = 'deployment_config_not_literal';

    /** The deployment configuration file, or the directory holding it, cannot be written by the tool's process. */
    case DeploymentConfigNotWritable = 'deployment_config_not_writable';

    /** The deployment configuration changed between reading a system value and writing it back. */
    case DeploymentConfigChanged = 'deployment_config_changed';

    /** The tool runs as another user than the owner of the deployment configuration. */
    case OtherUser = 'other_user';

    /** The state directory lies inside the web server's document root. */
    case StateDirectoryInDocroot = 'state_directory_in_docroot';

    /** The Magento root runs through a symbolic link and the state directory lies inside the release it points to. */
    case StateDirectoryInRelease = 'state_directory_in_release';

    /** Processes that may still hold an earlier key ring are running. */
    case WorkersRunning = 'workers_running';

    /** The web tier probe did not confirm the current key ring before anything was written. */
    case BaselineProbeFailed = 'baseline_probe_failed';

    /** The key given for the rotation cannot be appended to the ring. */
    case KeyRejected = 'key_rejected';

    /** A rollback started and did not finish; only the rollback may continue the run. */
    case RollbackInProgress = 'rollback_in_progress';

    /** The run has moved past the rotation (its old keys are being or were retired). */
    case RunPastRotation = 'run_past_rotation';

    /** The state directory holds no run the command could act on. */
    case NoRun = 'no_run';

    /** Another run, from this or another state directory, holds the store: one unfinished run per store until it is purged. */
    case RunClaimedElsewhere = 'run_claimed_elsewhere';

    /** The run's state does not allow the command (retiring before the values moved, purging an unfinished run). */
    case StateDoesNotAllow = 'state_does_not_allow';

    /** Retiring the old keys would leave values unreadable or skip a required step: values remain, embedded values or cut-short columns are unacknowledged, or the configuration cache was not cleaned. */
    case RetireBlocked = 'retire_blocked';

    /** Removing the new key would leave values unreadable: values remain under it (in the database, columns without a row key included, or in the deployment configuration), or embedded values or cut-short columns are unacknowledged. */
    case RollbackBlocked = 'rollback_blocked';

    /** The configuration cache could not be cleaned after values moved, and the operator did not clean it by hand. */
    case CacheNotCleaned = 'cache_not_cleaned';

    /** The run directory lacks key material the step needs (a kept key or the kept placeholders). */
    case KeptMaterialMissing = 'kept_material_missing';

    /** Values that only the run's kept keys decrypt remain on the indices a purge makes unreadable for good. */
    case ValuesStillReadable = 'values_still_readable';

    /** The deployed app/etc/config.php holds values under a key the step would remove; only a redeploy can move them. */
    case CommittedValuesOnRemovedKey = 'committed_values_on_removed_key';
}
