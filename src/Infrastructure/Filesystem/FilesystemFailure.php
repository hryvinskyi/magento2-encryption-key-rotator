<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Filesystem;

/**
 * A file operation failed: a file or directory could not be created, read, written, flushed, renamed or
 * removed. The message names the operation and the path, never the content of a file.
 */
final class FilesystemFailure extends \RuntimeException {}
