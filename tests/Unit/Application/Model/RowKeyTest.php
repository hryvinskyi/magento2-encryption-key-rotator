<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use PHPUnit\Framework\TestCase;

final class RowKeyTest extends TestCase
{
    public function testTheJsonKeepsTheKeyOrder(): void
    {
        self::assertSame('{"website_id":1,"code":"b"}', (new RowKey(['website_id' => 1, 'code' => 'b']))->toJson());
        self::assertSame('{"code":"b","website_id":1}', (new RowKey(['code' => 'b', 'website_id' => 1]))->toJson());
    }

    public function testTheJsonOfTheSameRowIsAlwaysTheSame(): void
    {
        $first = new RowKey(['entity_id' => 42, 'path' => 'payment/x/secret']);
        $second = new RowKey(['entity_id' => 42, 'path' => 'payment/x/secret']);

        self::assertSame($first->toJson(), $second->toJson());
        self::assertTrue($first->equals($second));
    }

    public function testKeysInAnotherOrderAreNotEqual(): void
    {
        self::assertFalse((new RowKey(['a' => 1, 'b' => 2]))->equals(new RowKey(['b' => 2, 'a' => 1])));
    }

    public function testAnIntegerAndItsStringAreDifferentKeys(): void
    {
        self::assertFalse((new RowKey(['id' => 1]))->equals(new RowKey(['id' => '1'])));
    }

    public function testNumericColumnNamesStayAnObjectAndAreReadBackAsNames(): void
    {
        $key = new RowKey([0 => 'a', 1 => 'b']);

        self::assertSame('{"0":"a","1":"b"}', $key->toJson());
        self::assertSame(['0', '1'], $key->columns());
    }

    public function testSlashesUnicodeAndFloatsAreWrittenExactly(): void
    {
        self::assertSame('{"path":"a/b","name":"Zürich","rate":1.0}', (new RowKey(['path' => 'a/b', 'name' => 'Zürich', 'rate' => 1.0]))->toJson());
    }

    public function testAKeyHasAtLeastOneColumn(): void
    {
        $this->expectException(InvalidValue::class);

        new RowKey([]);
    }

    public function testAValueThatIsNotUtf8IsRefused(): void
    {
        $this->expectException(InvalidValue::class);
        $this->expectExceptionMessage('"id"');

        new RowKey(['id' => "\xff\xfe"]);
    }
}
