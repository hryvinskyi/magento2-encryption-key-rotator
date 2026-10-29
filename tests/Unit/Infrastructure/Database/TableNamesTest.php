<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Infrastructure\Database;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\PdoConnectionProvider;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\TableNames;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Database\UnsupportedIdentifier;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\RecordingPdoFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\CryptoServices;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

/**
 * Table names carry the store's prefix, and only plain identifiers are ever quoted into a statement.
 */
final class TableNamesTest extends TestCase
{
    public function testTablesCarryThePrefixAndAreQuoted(): void
    {
        $names = $this->names('m2_');

        self::assertSame('m2_core_config_data', $names->physical('core_config_data'));
        self::assertSame('`m2_core_config_data`', $names->table('core_config_data'));
        self::assertSame('`m2_encryption_key_rotation_journal`', $names->journal());
        self::assertSame('`value`', $names->column('value'));
        self::assertSame('core_config_data', $names->logical('m2_core_config_data'));
    }

    public function testATableWithoutThePrefixIsNotOneOfTheStores(): void
    {
        $names = $this->names('m2_');

        self::assertNull($names->logical('core_config_data'));
        self::assertNull($names->logical('m2_'));
        self::assertSame('core_config_data', $this->names('')->logical('core_config_data'));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function unsupportedNames(): iterable
    {
        yield 'backtick' => ['a`b'];
        yield 'hyphen' => ['odd-name'];
        yield 'space' => ['a b'];
        yield 'dot' => ['a.b'];
        yield 'quote' => ["a'b"];
        yield 'empty' => [''];
        yield 'too long' => [str_repeat('a', 65)];
        yield 'not ASCII' => ['tablé'];
    }

    #[DataProvider('unsupportedNames')]
    public function testAnyOtherNameIsRefusedNeverEscaped(string $name): void
    {
        $names = $this->names('');

        self::assertFalse($names->isSupported($name));
        $this->expectException(UnsupportedIdentifier::class);

        $names->column($name);
    }

    public function testThePrefixCountsTowardsTheTablesName(): void
    {
        $names = $this->names('m2-');

        self::assertFalse($names->isSupportedTable('core_config_data'));
        $this->expectException(UnsupportedIdentifier::class);

        $names->table('core_config_data');
    }

    private function names(string $prefix): TableNames
    {
        $config = new InMemoryDeploymentConfig(
            CryptoServices::shared()->ringParser()->parse(KeyMaterial::base64Key()),
            databaseSettings: new DatabaseSettings('db', null, null, 'store', 'store', 'unused', $prefix, ''),
        );

        return new TableNames(new PdoConnectionProvider($config, new RecordingPdoFactory()));
    }
}
