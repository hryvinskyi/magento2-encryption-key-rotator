<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ColumnRefTest extends TestCase
{
    public function testTheQualifiedNameCarriesTheTablePrefix(): void
    {
        $column = new ColumnRef('core_config_data', 'value');

        self::assertSame('m2_core_config_data.value', $column->qualified('m2_'));
        self::assertSame('core_config_data.value', $column->qualified(''));
        self::assertSame('core_config_data.value', $column->toString());
    }

    public function testTwoReferencesToTheSameColumnAreEqual(): void
    {
        self::assertTrue((new ColumnRef('oauth_consumer', 'secret'))->equals(new ColumnRef('oauth_consumer', 'secret')));
        self::assertFalse((new ColumnRef('oauth_consumer', 'secret'))->equals(new ColumnRef('oauth_consumer', 'key')));
    }

    /**
     * @return iterable<string, array{string, string}>
     */
    public static function invalidNames(): iterable
    {
        yield 'an empty table' => ['', 'value'];
        yield 'an empty column' => ['core_config_data', ''];
        yield 'a dot in the table' => ['other.core_config_data', 'value'];
        yield 'a backtick' => ['core`config', 'value'];
        yield 'a NUL byte' => ["core\0config", 'value'];
        yield 'a name too long' => [str_repeat('t', 65), 'value'];
    }

    #[DataProvider('invalidNames')]
    public function testANameThatCannotBeATableOrColumnIsRefused(string $table, string $column): void
    {
        $this->expectException(InvalidValue::class);

        new ColumnRef($table, $column);
    }
}
