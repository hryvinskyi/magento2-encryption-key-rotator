<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Port;

/**
 * The run store's directory cannot be trusted or used: it, its parent or an entry below it belongs to
 * another user, is a symbolic link, or can be written by its group or others. Nothing was read from or
 * written to it; the operator passes a safe `--state-dir`. An adapter refines it with what exactly is
 * wrong.
 */
class UnusableStateDirectory extends \RuntimeException {}
