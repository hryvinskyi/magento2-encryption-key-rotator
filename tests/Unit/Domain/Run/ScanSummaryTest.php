<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Domain\Run;

use Hryvinskyi\EncryptionKeyRotator\Domain\Run\InvalidScanSummary;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummary;
use PHPUnit\Framework\TestCase;

final class ScanSummaryTest extends TestCase
{
    public function testCountsAreKeptPerIndexInIndexOrderWithoutEmptyIndices(): void
    {
        $summary = new ScanSummary([3 => 7, 0 => 2, 1 => 0], 4, 1, 0, []);

        self::assertSame([0 => 2, 3 => 7], $summary->verifiedPerIndex());
        self::assertSame(2, $summary->verifiedOn(0));
        self::assertSame(0, $summary->verifiedOn(1));
        self::assertSame(9, $summary->verifiedOnAny([0, 3, 3]));
        self::assertSame(4, $summary->undecryptable());
        self::assertTrue($summary->hasUnjudgedValues());
    }

    public function testAnIncompleteColumnIsAnUnjudgedValue(): void
    {
        self::assertTrue((new ScanSummary([], 0, 0, 1, []))->hasUnjudgedValues());
        self::assertFalse((new ScanSummary([2 => 5], 3, 0, 0, []))->hasUnjudgedValues());
    }

    public function testWholeValuesInColumnsWithoutARowKeyAreCountedPerIndexAndAreNotUnjudged(): void
    {
        $summary = new ScanSummary([], 0, 0, 0, [2 => 3, 0 => 1, 1 => 0]);

        self::assertSame([0 => 1, 2 => 3], $summary->withoutRowKeyPerIndex());
        self::assertSame(4, $summary->withoutRowKeyOnAny([0, 2, 2]));
        self::assertSame(0, $summary->withoutRowKeyOnAny([1]));
        self::assertFalse($summary->hasUnjudgedValues());
    }

    public function testANegativeCountWithoutARowKeyIsRefused(): void
    {
        $this->expectException(InvalidScanSummary::class);

        new ScanSummary([], 0, 0, 0, [1 => -1]);
    }

    public function testTheSnapshotListsIndicesExplicitly(): void
    {
        self::assertSame(
            ['verified' => [['index' => 0, 'count' => 2], ['index' => 3, 'count' => 7]], 'undecryptable' => 1, 'embedded' => 0, 'incomplete_columns' => 2, 'without_row_key' => [['index' => 1, 'count' => 4]]],
            (new ScanSummary([3 => 7, 0 => 2], 1, 0, 2, [1 => 4, 2 => 0]))->snapshot(),
        );
    }

    public function testANegativeCountIsRefused(): void
    {
        $this->expectException(InvalidScanSummary::class);

        new ScanSummary([0 => -1], 0, 0, 0, []);
    }

    public function testAKeyIndexOutOfRangeIsRefused(): void
    {
        $this->expectException(InvalidScanSummary::class);

        new ScanSummary([1000 => 1], 0, 0, 0, []);
    }

    public function testANegativeTotalIsRefused(): void
    {
        $this->expectException(InvalidScanSummary::class);
        $this->expectExceptionMessage('embedded');

        new ScanSummary([], 0, -2, 0, []);
    }
}
