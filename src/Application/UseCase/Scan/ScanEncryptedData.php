<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFinding;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueFindingFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\CiphertextRows;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\EncryptedColumnFinder;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Psr\Clock\ClockInterface;

/**
 * Scans the store's encrypted values, read-only: every candidate column of the database and the
 * encrypted `system` values of the deployment and the committed configuration.
 *
 * Every value is verified under the key of its index; a value is never changed. Extra keys stand in for
 * the ring's slots at their indices, so values on an index whose slot was retired or removed can be
 * verified with a key the run kept. Columns without a row key are listed with the counts discovery gave,
 * since their rows cannot be read one by one.
 */
final class ScanEncryptedData
{
    public const DEFAULT_BATCH_SIZE = 500;

    public function __construct(
        private readonly DeploymentConfigReader $config,
        private readonly EncryptedColumnFinder $finder,
        private readonly CiphertextRows $rows,
        private readonly CiphertextVerifier $verifier,
        private readonly ColumnFindingsFactory $columnFindings,
        private readonly SystemValueFindingFactory $systemValueFindings,
        private readonly ScanReportFactory $reports,
        private readonly Progress $progress,
        private readonly ClockInterface $clock,
    ) {}

    /**
     * @param ScanScope       $scope     the columns left out
     * @param array<int, Key> $extraKeys key index => key that stands in for the ring's slot at that index
     * @param int             $batchSize the most values read at once, at least 1
     *
     * @throws InvalidValue when the batch size is below 1
     */
    public function scan(ScanScope $scope, array $extraKeys = [], int $batchSize = self::DEFAULT_BATCH_SIZE): ScanReport
    {
        if ($batchSize < 1) {
            throw new InvalidValue('A scan reads at least one value at a time.');
        }
        $started = $this->clock->now();
        $ring = $this->config->keyRing();

        $this->progress->step('Discovering the columns that hold encrypted values');
        $columns = [];
        $withoutRowKey = [];
        foreach ($this->finder->candidates($scope) as $candidate) {
            if (!$candidate->hasRowKey()) {
                $withoutRowKey[] = $candidate;

                continue;
            }
            $columns[] = $this->verifyColumn($candidate, $ring, $extraKeys, $batchSize);
        }

        $this->progress->step('Verifying the encrypted values of the configuration files');
        $systemValues = array_map(
            fn(SystemValue $value): SystemValueFinding => $this->systemValueFindings->create(
                $value,
                $this->verifier->verdict($value->ciphertext(), $ring, $extraKeys),
            ),
            [...$this->config->systemValues(), ...$this->config->committedSystemValues()],
        );

        return $this->reports->create($columns, $withoutRowKey, $systemValues, $this->secondsSince($started));
    }

    /**
     * @param array<int, Key> $extraKeys
     */
    private function verifyColumn(ColumnCandidate $candidate, KeyRing $ring, array $extraKeys, int $batchSize): ColumnFindings
    {
        $column = $candidate->column();
        $this->progress->step(sprintf('Verifying %s', $column->toString()));
        $perIndex = [];
        foreach (array_keys($candidate->shapeCounts()) as $index) {
            $counts = [];
            foreach ($this->rows->batches($column, $index, $batchSize) as $batch) {
                foreach ($batch as $stored) {
                    $verdict = $this->verifier->verdictOnStored($stored->raw(), $ring, $extraKeys)->value;
                    $counts[$verdict] = ($counts[$verdict] ?? 0) + 1;
                }
                $this->progress->advance($column, count($batch));
            }
            $perIndex[$index] = $counts;
        }

        return $this->columnFindings->create($candidate, $perIndex);
    }

    private function secondsSince(\DateTimeImmutable $started): float
    {
        $elapsed = (float) $this->clock->now()->format('U.u') - (float) $started->format('U.u');

        return max(0.0, $elapsed);
    }
}
