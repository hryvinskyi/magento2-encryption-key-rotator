<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Why a run keeps a key in its run directory: it is the key the run appended (needed to read values
 * under the new index after a rollback removed it), or an old key the run retired (needed to undo the
 * retirement and to read stragglers left under its index).
 */
enum KeptKeyRole: string
{
    case Added = 'added';
    case Retired = 'retired';
}
