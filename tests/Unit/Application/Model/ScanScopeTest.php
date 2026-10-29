<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use PHPUnit\Framework\Attributes\DataProvider;
use PHPUnit\Framework\TestCase;

final class ScanScopeTest extends TestCase
{
    /**
     * @return iterable<string, array{list<string>, string, string, bool}>
     */
    public static function cases(): iterable
    {
        yield 'no pattern excludes nothing' => [[], 'sales_order', 'payment', false];
        yield 'a table pattern excludes every column' => [['sales_order'], 'sales_order', 'payment', true];
        yield 'a table pattern matches whole names only' => [['sales_order'], 'sales_order_grid', 'payment', false];
        yield 'a column pattern excludes that column' => [['sales_order.payment'], 'sales_order', 'payment', true];
        yield 'a column pattern leaves other columns' => [['sales_order.payment'], 'sales_order', 'email', false];
        yield 'a wildcard table' => [['sales_*'], 'sales_order_grid', 'payment', true];
        yield 'a wildcard matches an empty run' => [['sales_*'], 'sales_', 'x', true];
        yield 'a wildcard column' => [['*.secret_*'], 'oauth_consumer', 'secret_key', true];
        yield 'names compare case-sensitively' => [['Sales_order'], 'sales_order', 'payment', false];
        yield 'a dollar is literal' => [['t$1'], 't$1', 'c', true];
        yield 'any pattern of several' => [['a', 'b.c'], 'b', 'c', true];
    }

    /**
     * @param list<string> $patterns
     */
    #[DataProvider('cases')]
    public function testExcludes(array $patterns, string $table, string $column, bool $excluded): void
    {
        self::assertSame($excluded, (new ScanScope($patterns))->excludes(new ColumnRef($table, $column)));
    }

    /**
     * @return iterable<string, array{string}>
     */
    public static function malformedPatterns(): iterable
    {
        yield 'empty' => [''];
        yield 'two dots' => ['a.b.c'];
        yield 'a regular expression' => ['sales_(order|quote)'];
        yield 'a space' => ['sales order'];
        yield 'a trailing dot' => ['sales.'];
    }

    #[DataProvider('malformedPatterns')]
    public function testAMalformedPatternIsRefused(string $pattern): void
    {
        $this->expectException(InvalidValue::class);

        new ScanScope([$pattern]);
    }
}
