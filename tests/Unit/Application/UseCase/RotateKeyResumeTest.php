<?php

declare(strict_types=1);

namespace Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase;

use Hryvinskyi\EncryptionKeyRotator\Application\Model\ColumnRef;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\KeptKeyRole;
use Hryvinskyi\EncryptionKeyRotator\Application\Model\RowKey;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\Refusal;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Refusal\RefusalReason;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateRequest;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateResult;
use Hryvinskyi\EncryptionKeyRotator\Application\UseCase\Rotate\RotateStatus;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RotationRun;
use Hryvinskyi\EncryptionKeyRotator\Domain\Run\RunState;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\InMemoryDatabase;
use Hryvinskyi\EncryptionKeyRotator\Tests\Double\SequentialRunIdGenerator;
use Hryvinskyi\EncryptionKeyRotator\Tests\Support\KeyMaterial;
use Hryvinskyi\EncryptionKeyRotator\Tests\Unit\Application\UseCase\Support\RotationWorld;
use PHPUnit\Framework\TestCase;

/**
 * A rotation interrupted at any point is resumed by running it again: it reads the deployment
 * configuration as it is, never appends a second key, and finishes with the key it kept.
 */
final class RotateKeyResumeTest extends TestCase
{
    private RotationWorld $world;

    protected function setUp(): void
    {
        $this->world = (new RotationWorld())->seedDefault();
    }

    protected function tearDown(): void
    {
        $this->world->cleanUp();
    }

    public function testACrashAfterKeyPendingIsSavedButBeforeTheWriteIsResumedWithTheKeptKey(): void
    {
        $world = $this->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::KeyPending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after key_pending');
            }
        });

        $this->crash('crash after key_pending');

        $run = $world->runs->get(SequentialRunIdGenerator::id(1));
        self::assertSame(RunState::KeyPending, $run->state());
        self::assertSame([], $world->config->writes());
        self::assertSame($world->ringBefore->fingerprint(), $world->config->keyRing()->fingerprint());
        $kept = $world->runs->keptKeys($run->id(), KeptKeyRole::Added);
        self::assertCount(1, $kept, 'The key is kept before its write is announced.');

        $result = $world->rotate();

        $this->assertCompletedWithTheKeptKey($result, $kept[0]->raw());
        self::assertSame(1, $this->ringWrites(), 'The key ring is written once.');
    }

    public function testACrashAfterTheWriteButBeforeKeyAddedIsSavedOnlyRecordsTheWrite(): void
    {
        $world = $this->world;
        $world->config->afterWrite(function () use ($world): void {
            $world->config->afterWrite(null);

            throw new \RuntimeException('crash after the key write');
        });

        $this->crash('crash after the key write');

        $run = $world->runs->get(SequentialRunIdGenerator::id(1));
        self::assertSame(RunState::KeyPending, $run->state());
        self::assertSame($run->intendedRingFingerprint(), $world->config->keyRing()->fingerprint());
        $kept = $world->runs->keptKeys($run->id(), KeptKeyRole::Added);

        $result = $world->rotate();

        $this->assertCompletedWithTheKeptKey($result, $kept[0]->raw());
        self::assertSame(1, $this->ringWrites(), 'The write found in place is not made again.');
    }

    public function testACrashAfterTheFirstReencryptionBatchIsResumedAtTheReencryption(): void
    {
        $world = $this->world;
        $writes = 0;
        $world->database->beforeEachWrite(function () use ($world, &$writes): void {
            if (++$writes === 3) {
                $world->database->beforeEachWrite(null);

                throw new \RuntimeException('crash after the first batch');
            }
        });

        $this->crash('crash after the first batch', $world->request(batchSize: 2));

        $run = $world->runs->get(SequentialRunIdGenerator::id(1));
        self::assertSame(RunState::WebConfirmed, $run->state());
        $journaled = $world->database->journalEntries();
        self::assertCount(2, $journaled, 'The first batch is written and journaled.');
        $kept = $world->runs->keptKeys($run->id(), KeptKeyRole::Added);

        $result = $world->rotate($world->request(batchSize: 2));

        $this->assertCompletedWithTheKeptKey($result, $kept[0]->raw());
        self::assertCount(7, $world->database->journalEntries(), 'Every value is moved once.');
        self::assertSame(5, $result->reencryption()?->appliedTotal());
    }

    public function testAKeyPendingRunWhoseRingSomeoneElseChangedIsRefusedNamingEveryFingerprint(): void
    {
        $world = $this->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::KeyPending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after key_pending');
            }
        });
        $this->crash('crash after key_pending');
        $run = $world->runs->get(SequentialRunIdGenerator::id(1));
        $other = $world->ringParser->parse(KeyMaterial::base64Key() . "\n" . KeyMaterial::base64Key());
        $world->config->replaceRing($other);

        $result = $world->rotate();

        self::assertSame(RotateStatus::Refused, $result->status());
        self::assertSame([RefusalReason::RingChanged], array_map(static fn(Refusal $r): RefusalReason => $r->reason(), $result->refusals()));
        $message = $result->refusals()[0]->message();
        self::assertStringContainsString($other->fingerprint(), $message);
        self::assertStringContainsString($world->ringBefore->fingerprint(), $message);
        self::assertStringContainsString((string) $run->intendedRingFingerprint(), $message);
        self::assertSame([], $world->config->writes());
        self::assertSame(RunState::KeyPending, $world->runs->get($run->id())->state());
    }

    public function testARunInterruptedBeforeItsKeyWasKeptDrawsTheKeyOnceAndKeepsIt(): void
    {
        $world = $this->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::Started) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after the run started');
            }
        });
        $this->crash('crash after the run started');
        $keptBefore = $world->runs->keptKeys(SequentialRunIdGenerator::id(1), KeptKeyRole::Added);
        self::assertSame([], $keptBefore);

        $result = $world->rotate();

        $kept = $world->runs->keptKeys(SequentialRunIdGenerator::id(1), KeptKeyRole::Added);
        self::assertCount(1, $kept);
        $this->assertCompletedWithTheKeptKey($result, $kept[0]->raw());
    }

    public function testResumingWithAnotherKeyKeepsTheKeyTheRunAnnounced(): void
    {
        $world = $this->world;
        $world->runs->afterSave(function (RotationRun $run) use ($world): void {
            if ($run->state() === RunState::KeyPending) {
                $world->runs->afterSave(null);

                throw new \RuntimeException('crash after key_pending');
            }
        });
        $this->crash('crash after key_pending');
        $kept = $world->runs->keptKeys(SequentialRunIdGenerator::id(1), KeptKeyRole::Added)[0]->raw();

        $result = $world->rotate($world->request(rawKey: KeyMaterial::base64Key()));

        $this->assertCompletedWithTheKeptKey($result, $kept);
        self::assertNotSame([], $world->progress->warnings());
    }

    public function testAConflictCrashAndResumeStillLeaveTheStoresNewerValue(): void
    {
        $world = $this->world;
        $writes = 0;
        $world->database->beforeEachWrite(function (InMemoryDatabase $database, ColumnRef $column, RowKey $row) use ($world, &$writes): void {
            $writes++;
            if ($writes === 1) {
                $database->update('core_config_data', ['config_id' => 1], 'value', $world->encrypt('newer value', 1));
            }
            if ($writes === 2) {
                $world->database->beforeEachWrite(null);

                throw new \RuntimeException('crash during the first batch');
            }
        });
        $this->crash('crash during the first batch');

        $result = $world->rotate();

        self::assertSame(RotateStatus::Reencrypted, $result->status());
        self::assertSame('newer value', $world->decryptNow($world->value('core_config_data', 1, 'value', 'config_id')));
    }

    private function crash(string $message, ?RotateRequest $request = null): void
    {
        try {
            $this->world->rotate($request);
            self::fail('The crash hook did not run.');
        } catch (\RuntimeException $crash) {
            self::assertSame($message, $crash->getMessage());
        }
        $other = $this->world->runs->concurrentHandle();
        $other->lock();
        $other->unlock();
    }

    private function assertCompletedWithTheKeptKey(RotateResult $result, string $keptRaw): void
    {
        $world = $this->world;
        self::assertSame(RotateStatus::Reencrypted, $result->status(), implode("\n", array_map(static fn(Refusal $r): string => $r->message(), $result->refusals())));
        $ring = $world->config->keyRing();
        self::assertCount(4, $ring->slots(), 'Exactly one new slot.');
        self::assertSame($keptRaw, $ring->slot(3)?->raw(), 'The new slot holds the kept key.');
        $run = $world->runs->get($result->runId() ?? SequentialRunIdGenerator::id(1));
        self::assertSame(RunState::Reencrypted, $run->state());
        self::assertSame($ring->fingerprint(), $run->ringFingerprint());
        self::assertNull($world->runs->latest()?->intendedRingFingerprint());
        self::assertCount(1, $world->runs->keptKeys($run->id(), KeptKeyRole::Added));
        foreach ($world->seeded() as $where => $plaintext) {
            [$table, $id] = explode('#', $where);
            $value = $table === 'core_config_data'
                ? $world->value($table, (int) $id, 'value', 'config_id')
                : $world->value($table, (int) $id, 'secret');
            self::assertStringStartsWith('3:3:', $value, $where);
            self::assertSame($plaintext, $world->decryptNow($value), $where);
        }
    }

    /**
     * How many writes changed the key ring.
     */
    private function ringWrites(): int
    {
        $previous = $this->world->ringBefore->fingerprint();
        $changes = 0;
        foreach ($this->world->config->writes() as $write) {
            if ($write['ring']->fingerprint() !== $previous) {
                $changes++;
                $previous = $write['ring']->fingerprint();
            }
        }

        return $changes;
    }
}
