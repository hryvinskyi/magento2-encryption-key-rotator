<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Runtime;

/**
 * The effective user id of the tool's process could not be determined.
 */
final class UserIdUnavailable extends \RuntimeException {}
