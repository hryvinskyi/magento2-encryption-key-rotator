<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Integration\Build;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnCandidateFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\DatabaseSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettings;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeSettingsFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\ProbeTransportKind;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKeyFactory;
use Hryvinskyi\EncryptionKeyRotator\Application\Run\RunSnapshotReader;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRunFactory;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunOverride;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\ScanSummaryFactory;
use Hryvinskyi\EncryptionKeyRotator\Infrastructure\Run\RandomRunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\RunServices;
use PHPUnit\Framework\TestCase;

/**
 * A run starts, moves and is read back from its snapshot through the generated factories and bindings
 * of the real container, and the factories of the values the ports exchange build those values.
 */
final class RunWiringTest extends TestCase
{
    private RunServices $services;

    protected function setUp(): void
    {
        $this->services = RunServices::shared();
    }

    public function testARunStartedThroughTheContainerIsReadBackFromItsSnapshot(): void
    {
        $generator = $this->services->get(RunIdGenerator::class);
        $id = $generator->next();
        $at = new \DateTimeImmutable('2026-10-29T10:00:00.123456+00:00');
        $run = $this->services->get(RotationRunFactory::class)->start($id, '00000000000000aa', [0], 1, $at);
        $run->keyPending(2, '00000000000000bb', $at->add(new \DateInterval('PT1S')));
        $run->keyAdded('00000000000000bb', $at->add(new \DateInterval('PT2S')));
        $run->webConfirmed(true, $at->add(new \DateInterval('PT3S')));
        $run->reencrypted($this->services->get(ScanSummaryFactory::class)->create([2 => 40], 1, 0, 0, [1 => 3]), true, $at->add(new \DateInterval('PT4S')));
        $json = json_encode($run->snapshot(), JSON_THROW_ON_ERROR);

        $restored = $this->services->get(RunSnapshotReader::class)->read($id->toString(), json_decode($json, true, 512, JSON_THROW_ON_ERROR));

        self::assertInstanceOf(RandomRunIdGenerator::class, $generator);
        self::assertSame(RunState::Started, $run->history()[0]['state']);
        self::assertSame(RunState::Reencrypted, $restored->state());
        self::assertSame([RunOverride::SkipWebProbe], array_map(static fn(array $o): RunOverride => $o['override'], $restored->overrides()));
        self::assertSame($run->snapshot(), $restored->snapshot());
    }

    public function testTheFactoriesOfPortValuesBuildThem(): void
    {
        $key = $this->services->get(RowKeyFactory::class)->create(['website_id' => 1, 'code' => 'x']);
        $settings = $this->services->get(DatabaseSettingsFactory::class)->create('db', 3306, null, 'store', 'store', 'secret', 'm2_', '');
        $probe = $this->services->get(ProbeSettingsFactory::class)->create('tcp://fpm:9000', null, null, ProbeSettings::DEFAULT_DOCROOT, true, 10, false);
        $candidate = $this->services->get(ColumnCandidateFactory::class)->create(new ColumnRef('customer_entity', 'rp_token'), ['entity_id'], ['updated_at'], [1 => 3], 0, false);

        self::assertSame('{"website_id":1,"code":"x"}', $key->toJson());
        self::assertSame('m2_', $settings->tablePrefix());
        self::assertSame(ProbeTransportKind::FastCgi, $probe->transport());
        self::assertSame(3, $candidate->shapeCountOn(1));
        self::assertSame(['updated_at'], $candidate->autoUpdatedColumns());
    }
}
