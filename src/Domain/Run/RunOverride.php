<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Domain\Run;

/**
 * A safety check the operator explicitly waived. A run records every waiver with the state it was
 * given in, so the run file shows afterwards which guarantees the rotation went without.
 */
enum RunOverride: string
{
    /** Processes that started before the last key ring write were left running while values moved. */
    case IgnoreWorkers = 'ignore_workers';

    /** The tool ran as another user than the owner of the deployment configuration. */
    case AllowOtherUser = 'allow_other_user';

    /** A key ring change was not confirmed against the web tier. */
    case SkipWebProbe = 'skip_web_probe';

    /** Old keys were retired although values on their indices still decrypted, or sat in columns without a row key. */
    case AcceptRemaining = 'accept_remaining';

    /** Old keys were retired, or a rolled-back key removed, although values embedded in larger values, or columns not fully scanned, were found. */
    case AcceptEmbedded = 'accept_embedded';

    /** Old keys were retired on the operator's word that the configuration cache was cleaned. */
    case CacheCleanedManually = 'cache_cleaned_manually';

    /** The kept keys were destroyed although values that only they decrypt remained. */
    case AcceptLoss = 'accept_loss';
}
