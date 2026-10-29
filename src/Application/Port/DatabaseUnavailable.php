<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The store's database could not be reached, or refused the statements configured to run on a new
 * connection. The message names the host, the database and the server's error code, never the user's
 * password.
 */
final class DatabaseUnavailable extends \RuntimeException {}
