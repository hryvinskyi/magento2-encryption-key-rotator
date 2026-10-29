<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run;

use Hryvinskyi\EncryptionKeyRotator\Application\Port\UnusableStateDirectory;

/**
 * The state directory, its parent, or an entry below it is not safe to use: another account could
 * write there, or an entry is a symbolic link or belongs to another user. Raised before anything is read
 * from or written to that place. The message names the path, what is wrong with it and what to do.
 */
final class UntrustedStateDirectory extends UnusableStateDirectory {}
