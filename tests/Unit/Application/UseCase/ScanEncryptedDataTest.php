<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidate;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnFindings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanReport;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ValueVerdict;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\Progress;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\CiphertextVerifier;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Scan\ScanEncryptedData;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectColumnFindingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectScanReportFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueFindingFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;
use Symfony\Component\Clock\MockClock;

/**
 * The scan verifies every stored value under the key of its index, says why a value does not decrypt,
 * lists what it cannot judge, and keeps no plaintext.
 */
final class ScanEncryptedDataTest extends TestCase
{
    private RotationWorld $world;

    protected function setUp(): void
    {
        $this->world = new RotationWorld();
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
    }

    public function testEveryValueIsCountedUnderItsIndexWithTheReasonItDoesNotDecrypt(): void
    {
        $this->seedEveryVerdict();

        $report = $this->world->scanner->scan(new ScanScope([]));

        $findings = $this->findingsOf($report, 'secrets.value');
        self::assertSame(2, $findings->verifiedOn(1));
        self::assertSame(1, $findings->count(1, ValueVerdict::UnsupportedCipher));
        self::assertSame(1, $findings->count(1, ValueVerdict::AuthenticationFailed));
        self::assertSame(1, $findings->count(1, ValueVerdict::Unparsable));
        self::assertSame(1, $findings->verifiedOn(2));
        self::assertSame(1, $findings->count(0, ValueVerdict::RetiredKey));
        self::assertSame(1, $findings->count(7, ValueVerdict::UnknownKey));
        self::assertSame([0, 1, 2, 7], $findings->indices());

        $totals = $report->totalsPerIndex();
        self::assertSame(['verified' => 3, 'retired_key' => 0, 'unknown_key' => 0, 'unsupported_cipher' => 1, 'authentication_failed' => 1, 'unparsable' => 1], $totals[1]);
        self::assertSame(1, $totals[0]['retired_key']);
        self::assertSame(1, $totals[7]['unknown_key']);
        self::assertSame(2, $totals[2]['verified'], 'The deployment configuration value counts with the column.');

        $summary = $report->summary();
        self::assertSame([1 => 3, 2 => 2], $summary->verifiedPerIndex());
        self::assertSame(5, $summary->undecryptable());
        self::assertSame(0, $summary->embedded());
        self::assertSame(0, $summary->incompleteColumns());
    }

    public function testSystemValuesOfBothFilesAreVerifiedAndTaggedWithTheirFile(): void
    {
        $report = $this->world->scanner->scan(new ScanScope([]));

        $env = $report->systemValues(SystemValueSource::Env);
        $committed = $report->systemValues(SystemValueSource::Committed);
        self::assertCount(1, $env);
        self::assertCount(1, $committed);
        self::assertSame('payment/gateway/api_secret', $env[0]->value()->pathString());
        self::assertSame(2, $env[0]->keyIndex());
        self::assertSame(ValueVerdict::Verified, $env[0]->verdict());
        self::assertSame('carriers/courier/password', $committed[0]->value()->pathString());
        self::assertSame(1, $committed[0]->keyIndex());
        self::assertSame(ValueVerdict::Verified, $committed[0]->verdict());
        self::assertSame([1 => 1, 2 => 1], $report->summary()->verifiedPerIndex());
        self::assertSame(1, $report->verifiedOnAny([1]), 'A committed value on an old index keeps the old key needed.');
    }

    public function testEmbeddedNoRowKeyAndIncompleteColumnsAreListedApart(): void
    {
        $this->world->database->createTable('sales_payment', ['entity_id'], ['additional_information']);
        $this->world->database->insert('sales_payment', [
            'entity_id' => 1,
            'additional_information' => json_encode(['token' => $this->world->encrypt('embedded secret', 2)], JSON_THROW_ON_ERROR | JSON_UNESCAPED_SLASHES),
        ]);
        $this->world->database->createTable('legacy_token', [], ['token']);
        $this->world->database->insert('legacy_token', ['token' => $this->world->encrypt('keyless secret', 1)]);
        $this->world->database->insert('legacy_token', ['token' => $this->world->encrypt('keyless secret 2', 2)]);
        $this->world->database->createTable('import_log', ['entity_id'], ['payload']);
        $this->world->database->insert('import_log', ['entity_id' => 1, 'payload' => $this->world->encrypt('long secret', 1)]);
        $this->world->database->cutScanShort('import_log', 'payload');

        $report = $this->world->scanner->scan(new ScanScope([]));

        self::assertSame(['sales_payment.additional_information'], $this->names($report->embeddedCandidates()));
        self::assertSame(1, $report->embeddedCandidates()[0]->embeddedCount());
        self::assertSame(['legacy_token.token'], $this->names($report->columnsWithoutRowKey()));
        self::assertSame([1 => 1, 2 => 1], $report->columnsWithoutRowKey()[0]->shapeCounts());
        self::assertSame(['import_log.payload'], $this->names($report->incompleteColumns()));
        self::assertSame(1, $this->findingsOf($report, 'import_log.payload')->verifiedOn(1), 'What the column yields is still verified.');

        $summary = $report->summary();
        self::assertSame(1, $summary->embedded());
        self::assertSame(1, $summary->incompleteColumns(), 'Only the cut-short column is not judged in full.');
        self::assertTrue($summary->hasUnjudgedValues());
        self::assertSame([1 => 2, 2 => 1], $summary->verifiedPerIndex(), 'The cut-short column and both files count; the values without a row key do not.');
        self::assertSame([1 => 1, 2 => 1], $summary->withoutRowKeyPerIndex(), 'The whole ciphertexts without a row key are counted per key index, not as embedded.');
        self::assertSame(1, $summary->withoutRowKeyOnAny([1]));
    }

    public function testExtraKeysStandInForTheSlotsAtTheirIndices(): void
    {
        $retiredKey = new Key(KeyMaterial::base64Key());
        $removedKey = new Key(KeyMaterial::base64Key());
        $this->world->database->createTable('secrets', ['entity_id'], ['value']);
        $this->world->database->insert('secrets', ['entity_id' => 1, 'value' => $this->world->encrypt('under a retired slot', 0, $retiredKey)]);
        $this->world->database->insert('secrets', ['entity_id' => 2, 'value' => $this->world->encrypt('under a removed slot', 3, $removedKey)]);

        $without = $this->findingsOf($this->world->scanner->scan(new ScanScope([])), 'secrets.value');
        $with = $this->findingsOf($this->world->scanner->scan(new ScanScope([]), [0 => $retiredKey, 3 => $removedKey]), 'secrets.value');

        self::assertSame(1, $without->count(0, ValueVerdict::RetiredKey));
        self::assertSame(1, $without->count(3, ValueVerdict::UnknownKey));
        self::assertSame(1, $with->verifiedOn(0));
        self::assertSame(1, $with->verifiedOn(3));
    }

    public function testTheScopeLeavesColumnsOut(): void
    {
        $this->world->seedDefault();

        $report = $this->world->scanner->scan(new ScanScope(['oauth_*']));

        self::assertSame(['core_config_data.value'], array_map(static fn(ColumnFindings $f): string => $f->column()->toString(), $report->columns()));
    }

    public function testTheReportHoldsNoPlaintextAndTellsNone(): void
    {
        $this->world->seedDefault();
        $this->seedEveryVerdict();

        $report = $this->world->scanner->scan(new ScanScope([]));

        $renderings = [
            serialize($report),
            json_encode($report->toArray(), JSON_THROW_ON_ERROR),
            print_r($report, true),
            $this->world->progress->transcript(),
        ];
        self::assertNotEmpty($this->world->plaintexts());
        foreach ($renderings as $rendering) {
            foreach ($this->world->plaintexts() as $plaintext) {
                self::assertStringNotContainsString($plaintext, $rendering);
            }
        }
        self::assertSame($report->summary()->snapshot(), $report->toArray()['summary']);
    }

    public function testTheElapsedTimeIsMeasuredOnTheClock(): void
    {
        $clock = $this->world->clock;
        $sleepingProgress = new class ($clock) implements Progress {
            public function __construct(
                private readonly MockClock $clock,
            ) {}

            public function step(string $message): void
            {
                $this->clock->sleep(1.25);
            }

            public function advance(ColumnRef $column, int $count): void {}

            public function warn(string $message): void {}
        };
        $world = $this->world;
        $scanner = new ScanEncryptedData(
            $world->config,
            $world->database,
            $world->database,
            new CiphertextVerifier($world->ciphertextParser, $world->cipher, new DirectKeyFactory()),
            new DirectColumnFindingsFactory(),
            new DirectSystemValueFindingFactory(),
            new DirectScanReportFactory(),
            $sleepingProgress,
            $clock,
        );

        $report = $scanner->scan(new ScanScope([]));

        self::assertEqualsWithDelta(2.5, $report->elapsedSeconds(), 0.000001, 'Two steps of 1.25 s each.');
    }

    public function testABatchSizeBelowOneIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->world->scanner->scan(new ScanScope([]), [], 0);
    }

    private function seedEveryVerdict(): void
    {
        $world = $this->world;
        $world->database->createTable('secrets', ['entity_id'], ['value']);
        $world->database->insert('secrets', ['entity_id' => 1, 'value' => $world->encrypt('verified under the old key', 1)]);
        $world->database->insert('secrets', ['entity_id' => 2, 'value' => $world->encrypt('verified under the old key too', 1)]);
        $world->database->insert('secrets', ['entity_id' => 3, 'value' => $world->encrypt('verified under the active key', 2)]);
        $world->database->insert('secrets', ['entity_id' => 4, 'value' => $world->encrypt('under the retired slot', 0, new Key(KeyMaterial::base64Key()))]);
        $world->database->insert('secrets', ['entity_id' => 5, 'value' => $world->encrypt('under a slot the ring lacks', 7, new Key(KeyMaterial::base64Key()))]);
        $world->database->insert('secrets', ['entity_id' => 6, 'value' => '1:2:' . base64_encode(random_bytes(48))]);
        $world->database->insert('secrets', ['entity_id' => 7, 'value' => $world->encrypt('under a foreign key', 1, new Key(KeyMaterial::base64Key()))]);
        $world->database->insert('secrets', ['entity_id' => 8, 'value' => '1:3:' . str_repeat('A', 40) . 'AB==']);
    }

    private function findingsOf(ScanReport $report, string $column): ColumnFindings
    {
        foreach ($report->columns() as $findings) {
            if ($findings->column()->toString() === $column) {
                return $findings;
            }
        }
        self::fail(sprintf('The report has no findings for %s.', $column));
    }

    /**
     * @param list<ColumnCandidate> $candidates
     *
     * @return list<string>
     */
    private function names(array $candidates): array
    {
        return array_map(static fn(ColumnCandidate $candidate): string => $candidate->column()->toString(), $candidates);
    }
}
