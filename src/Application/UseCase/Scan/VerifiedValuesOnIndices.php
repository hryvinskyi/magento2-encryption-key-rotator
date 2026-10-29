<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;

/**
 * Tells where a scan found values that still need some key indices: values that decrypt under them in
 * the database, in the deployment configuration, or in the committed configuration, and whole
 * ciphertexts under them in columns without a row key. Each place is fixed differently (the committed
 * configuration is tracked and deployed, so its values are re-encrypted in the repository; a column
 * without a row key cannot be rewritten by the tool at all), so an operator told that values remain
 * needs to know which.
 */
final class VerifiedValuesOnIndices
{
    /**
     * @param list<int> $indices
     */
    public function inDatabase(ScanReport $scan, array $indices): int
    {
        $total = 0;
        foreach ($scan->columns() as $findings) {
            foreach (array_unique($indices) as $index) {
                $total += $findings->verifiedOn($index);
            }
        }

        return $total;
    }

    /**
     * @param list<int> $indices
     */
    public function inFile(ScanReport $scan, SystemValueSource $source, array $indices): int
    {
        $total = 0;
        foreach ($scan->systemValues($source) as $finding) {
            if ($finding->verdict() === ValueVerdict::Verified && in_array($finding->keyIndex(), $indices, true)) {
                $total++;
            }
        }

        return $total;
    }

    /**
     * The columns without a row key holding whole ciphertexts under those indices.
     *
     * @param list<int> $indices
     *
     * @return array<string, int> `table.column` => values under those indices
     */
    public function withoutRowKey(ScanReport $scan, array $indices): array
    {
        $columns = [];
        foreach ($scan->columnsWithoutRowKey() as $candidate) {
            $count = 0;
            foreach (array_unique($indices) as $index) {
                $count += $candidate->shapeCountOn($index);
            }
            if ($count > 0) {
                $columns[$candidate->column()->toString()] = $count;
            }
        }

        return $columns;
    }

    /**
     * The places holding such values, as a phrase for the operator (`2 in the database, 1 in the
     * committed configuration (app/etc/config.php: re-encrypt it in the repository and deploy it)`), or
     * an empty string when there are none.
     *
     * @param list<int> $indices
     */
    public function describe(ScanReport $scan, array $indices): string
    {
        $places = [];
        $database = $this->inDatabase($scan, $indices);
        if ($database > 0) {
            $places[] = sprintf('%d in the database', $database);
        }
        $env = $this->inFile($scan, SystemValueSource::Env, $indices);
        if ($env > 0) {
            $places[] = sprintf('%d in the deployment configuration (app/etc/env.php)', $env);
        }
        $committed = $this->inFile($scan, SystemValueSource::Committed, $indices);
        if ($committed > 0) {
            $places[] = sprintf('%d in the committed configuration (app/etc/config.php: re-encrypt it in the repository and deploy it)', $committed);
        }
        $withoutRowKey = $this->withoutRowKey($scan, $indices);
        if ($withoutRowKey !== []) {
            $places[] = sprintf(
                '%d in columns whose table has no row key, which the tool cannot rewrite (%s: give the table a primary or unique key, or move the values by hand)',
                array_sum($withoutRowKey),
                implode(', ', array_keys($withoutRowKey)),
            );
        }

        return implode(', ', $places);
    }
}
