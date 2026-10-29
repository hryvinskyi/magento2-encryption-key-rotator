<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\Model;

use Hryvinskyi\EncryptionKeyRotator\Kernel\Attribute\CreatesInstancesOf;

/**
 * Creates {@see ScanReport} values; implemented by the container build, which also hands the report the
 * summary factory it needs.
 */
#[CreatesInstancesOf(ScanReport::class)]
interface ScanReportFactory
{
    /**
     * @param list<ColumnFindings>     $columns
     * @param list<ColumnCandidate>    $withoutRowKey
     * @param list<SystemValueFinding> $systemValues
     *
     * @throws InvalidValue when the elapsed time is negative
     */
    public function create(array $columns, array $withoutRowKey, array $systemValues, float $elapsedSeconds): ScanReport;
}
