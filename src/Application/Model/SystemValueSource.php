<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

/**
 * Which configuration file holds a `system` value: the deployment configuration (`app/etc/env.php`),
 * which the tool writes, or the committed configuration (`app/etc/config.php`), which is tracked and
 * deployed and which the tool therefore only reads.
 */
enum SystemValueSource: string
{
    case Env = 'env';
    case Committed = 'committed';
}
