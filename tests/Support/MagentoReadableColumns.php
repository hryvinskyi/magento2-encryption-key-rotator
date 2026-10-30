<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Support;

/**
 * The column definitions the tool's own tables may have, as information_schema.COLUMNS reports them
 * on MariaDB 10.6 and MySQL 8.0, keyed by DATA_TYPE.
 *
 * Two suites hold the list to its meaning: the integration suite checks that every column of the
 * tool's tables is one of these definitions, and the compatibility suite checks that Magento's own
 * schema reader, which `setup:upgrade` runs over every table of the database, reads each of them.
 */
final class MagentoReadableColumns
{
    /**
     * @var array<string, list<string>>
     */
    public const DEFINITIONS = [
        'bigint' => ['bigint(20) unsigned', 'bigint unsigned'],
        'tinyint' => ['tinyint(3) unsigned', 'tinyint unsigned'],
        'char' => ['char(32)'],
        'varchar' => ['varchar(8)', 'varchar(64)'],
        'text' => ['text'],
        'longblob' => ['longblob'],
        'datetime' => ['datetime'],
    ];
}
