<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Why a compare-and-swap wrote nothing: the row holds another value than the one expected, or the row
 * is gone.
 */
enum ConflictReason: string
{
    case Changed = 'changed';
    case Missing = 'missing';
}
