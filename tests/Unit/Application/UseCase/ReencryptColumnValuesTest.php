<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ConflictReason;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\Direction;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\InvalidValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ScanScope;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValue;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueSource;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\SystemValueChange;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\DeploymentConfigReader;
use Hryvinskyi\EncryptionKeyRotator\Application\Port\StaleDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Reencryption\SystemValueReencryption;
use Hryvinskyi\EncryptionKeyRotator\Domain\Crypto\Ciphertext;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\Key;
use Hryvinskyi\EncryptionKeyRotator\Domain\Key\KeyRing;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunId;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\Factory\DirectSystemValueChangeFactory;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDeploymentConfig;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * The shared re-encryption moves values between any keys, in either direction, never writes over a
 * value that changed, and reports what it left behind instead of failing.
 */
final class ReencryptColumnValuesTest extends TestCase
{
    private const RUN = '0000000000000000000000000000000a';

    private RotationWorld $world;

    private Key $target;

    protected function setUp(): void
    {
        $this->world = (new RotationWorld())->seedDefault();
        $this->target = new Key(KeyMaterial::base64Key());
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
    }

    public function testValuesMoveBackOntoAnEarlierKeyJournaledAsBack(): void
    {
        $world = $this->world;

        $outcome = $world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Back, [2 => $world->key(2)], 1, $world->key(1), new ScanScope([]), 10);

        self::assertSame(4, $outcome->appliedTotal());
        self::assertSame(['core_config_data.value' => 2, 'oauth_consumer.secret' => 2], $outcome->applied());
        self::assertSame(1, $outcome->passes());
        self::assertSame(0, $outcome->remainingTotal());
        foreach ($world->database->journalEntries(new RunId(self::RUN)) as $entry) {
            self::assertSame(Direction::Back, $entry->direction());
            self::assertStringStartsWith('1:3:', $entry->newRaw());
        }
        self::assertSame('config secret 4', $world->decryptNow($world->value('core_config_data', 4, 'value', 'config_id')));
        self::assertSame('0', (string) $world->database->value('oauth_consumer', ['entity_id' => 1], 'updated_at'), 'Automatically updated columns keep their values.');
    }

    public function testAValueTheStoreKeepsRewritingIsReportedAfterThreePasses(): void
    {
        $world = $this->world;
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $row) use ($world): void {
            if ($row->values() === ['config_id' => 1]) {
                $database->update('core_config_data', ['config_id' => 1], 'value', $world->encrypt('rewritten again', 1));
            }
        });

        $outcome = $world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [1 => $world->key(1)], 3, $this->target, new ScanScope(['oauth_consumer']), 10);

        self::assertSame(3, $outcome->passes());
        self::assertCount(1, $outcome->conflicts());
        self::assertSame(ConflictReason::Changed, $outcome->conflicts()[0]->reason());
        self::assertSame(['config_id' => 1], $outcome->conflicts()[0]->rowKey()->values());
        self::assertSame(2, $outcome->appliedTotal());
        self::assertSame(1, $outcome->remainingTotal());
        self::assertSame('rewritten again', $world->decryptNow($world->value('core_config_data', 1, 'value', 'config_id')));
    }

    public function testAColumnWithoutARowKeyIsNeverWritten(): void
    {
        $world = $this->world;
        $world->database->createTable('legacy_token', [], ['token']);
        $raw = $world->encrypt('keyless', 1);
        $world->database->insert('legacy_token', ['token' => $raw]);

        $outcome = $world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [1 => $world->key(1)], 3, $this->target, new ScanScope([]), 10);

        self::assertSame($raw, $world->database->rows('legacy_token')[0]['token']);
        self::assertSame(0, $outcome->appliedTo(new ColumnRef('legacy_token', 'token')));
    }

    public function testRunningItAgainTouchesNothingItMoved(): void
    {
        $world = $this->world;
        $world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [1 => $world->key(1), 2 => $world->key(2)], 3, $this->target, new ScanScope([]), 2);
        $journal = count($world->database->journalEntries());

        $again = $world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [1 => $world->key(1), 2 => $world->key(2)], 3, $this->target, new ScanScope([]), 2);

        self::assertSame(0, $again->appliedTotal());
        self::assertSame(0, $again->passes());
        self::assertCount($journal, $world->database->journalEntries());
    }

    public function testATargetAmongTheSourcesIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [1 => $this->world->key(1)], 1, $this->world->key(1), new ScanScope([]), 10);
    }

    public function testNoSourceIsRefused(): void
    {
        $this->expectException(InvalidValue::class);

        $this->world->columnReencryption->reencrypt(new RunId(self::RUN), Direction::Forward, [], 3, $this->target, new ScanScope([]), 10);
    }

    public function testSystemValuesMoveInOneWriteOfTheFile(): void
    {
        $world = $this->world;
        $world->config->putSystemValue(new SystemValue(['payment', 'other', 'key'], $world->ciphertext('other secret', 1), SystemValueSource::Env));
        $service = new SystemValueReencryption($world->config, $world->config, $world->cipher, new DirectSystemValueChangeFactory());

        $changes = $service->reencrypt([1 => $world->key(1), 2 => $world->key(2)], 3, $this->target, $world->ringBefore, $world->ringBefore->fingerprint());

        self::assertSame(['payment/gateway/api_secret', 'payment/other/key'], array_map(static fn(SystemValueChange $change): string => $change->pathString(), $changes));
        self::assertCount(1, $world->config->writes());
        self::assertSame($world->ringBefore->fingerprint(), $world->config->keyRing()->fingerprint(), 'The ring is written unchanged.');
        foreach ($world->config->systemValues() as $value) {
            self::assertSame(3, $value->ciphertext()->keyIndex());
        }
    }

    public function testASystemValueChangedBetweenTheReadAndTheWriteIsNeverOverwritten(): void
    {
        $world = $this->world;
        $config = $world->config;
        $racingReader = new class ($config, $world->ciphertext('written meanwhile', 2)) implements DeploymentConfigReader {
            public function __construct(
                private readonly InMemoryDeploymentConfig $inner,
                private readonly Ciphertext $meanwhile,
            ) {}

            public function keyRing(): KeyRing
            {
                return $this->inner->keyRing();
            }

            public function databaseSettings(): DatabaseSettings
            {
                return $this->inner->databaseSettings();
            }

            public function systemValues(): array
            {
                $values = $this->inner->systemValues();
                $this->inner->putSystemValue(new SystemValue(RotationWorld::ENV_PATH, $this->meanwhile, SystemValueSource::Env));

                return $values;
            }

            public function committedSystemValues(): array
            {
                return $this->inner->committedSystemValues();
            }

            public function ownerUid(): int
            {
                return $this->inner->ownerUid();
            }

            public function holdsOnlyLiteralData(): bool
            {
                return $this->inner->holdsOnlyLiteralData();
            }

            public function isWritable(): bool
            {
                return $this->inner->isWritable();
            }

            public function secretStrings(): array
            {
                return $this->inner->secretStrings();
            }
        };
        $service = new SystemValueReencryption($racingReader, $config, $world->cipher, new DirectSystemValueChangeFactory());

        try {
            $service->reencrypt([2 => $world->key(2)], 3, $this->target, $world->ringBefore, $world->ringBefore->fingerprint());
            self::fail('A value changed between the read and the write was overwritten.');
        } catch (StaleDeploymentConfig) {
            self::assertSame([], $config->writes());
            self::assertSame('written meanwhile', $world->decryptNow($config->systemValues()[0]->ciphertext()->toString()));
        }
    }
}
