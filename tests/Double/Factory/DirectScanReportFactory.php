<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;

/**
 * Stands in for the generated factory in tests that run without the container.
 */
final class DirectScanReportFactory implements ScanReportFactory
{
    public function __construct(
        private readonly ScanSummaryFactory $summaries = new DirectScanSummaryFactory(),
    ) {}

    public function create(array $columns, array $withoutRowKey, array $systemValues, float $elapsedSeconds): ScanReport
    {
        return new ScanReport($columns, $withoutRowKey, $systemValues, $elapsedSeconds, $this->summaries);
    }
}
