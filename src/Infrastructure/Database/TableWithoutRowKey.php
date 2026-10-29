<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database;

/**
 * Rows of a table were asked for by key, but the table has no row key: no primary key and no unique
 * index over NOT NULL columns. Such a table is reported, never paged or written.
 */
final class TableWithoutRowKey extends \LogicException {}
